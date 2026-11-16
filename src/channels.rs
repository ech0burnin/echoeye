//! M4.4 (task folder `m42-channels`): network-replicated delivery
//! channels with monotonic versioning.
//!
//! The first delivery channel is ntfy push (M4.1 semantics); the shape
//! is deliberately channel-agnostic — [`DeliveryChannel`] is a
//! type-tagged set of parameters, so later miles can add
//! telegram/matrix/email variants without a wire break (the tag rides
//! inside the gossip payload, old binaries ignore the whole field).
//!
//! Ownership model — why this is NOT a `NetworkConfig` field: the
//! daemon re-persists network.toml every gossip round, so anything
//! stored in the config would either be clobbered by the rewrite or
//! fight the merge. The network channel lives in
//! `NodeState.channels` (runtime-only, like probes) plus a best-effort
//! `channel.json` cache next to network.toml. The cache matters for
//! the cold start of the whole mesh: if every node (parent included)
//! reboots, a runtime-only channel would be lost forever — nobody
//! would ever re-announce it. The cache is written only when the
//! version advances; the strictly-greater merge rule then guarantees
//! all caches converge.
//!
//! Merge semantics (Artyom's rule, 2026-11-15): incoming state is
//! applied ONLY when `incoming.version > local.version`. Equal, older
//! or duplicate versions are no-ops — protection against out-of-order
//! gossip and rapid channel switches where any "latest write wins"
//! scheme could silently lose a channel. Known split-brain caveat:
//! two self-elected parents in a partition both accepting channel-set
//! produce diverging versions; once the partition heals the higher
//! version wins and the loser's set is silently dropped. Accepted for
//! a 2-node mesh, documented here.
//!
//! Local override: a node's own `[ntfy]` section beats the network
//! channel (test nodes pushing to a separate topic) — see [`resolve`].
//!
//! Secrets: the ntfy topic doubles as a push credential. It rides the
//! gossip perimeter (every mesh node knows url+topic — accepted in the
//! task brief, same trust level as the network secret) but is never
//! logged verbatim: [`mask_topic`] (same 3-char rule as the CLI)
//! everywhere. `channel.json` stores the topic in the clear next to
//! network.toml — same protection class as the config file itself
//! (network.toml also holds the network secret with default perms).

use crate::ntfy::{NtfySection, DEFAULT_PRIORITY_DOWN, DEFAULT_PRIORITY_RECOVERED};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Cache file name, written next to network.toml (same directory).
pub const CACHE_FILENAME: &str = "channel.json";

fn default_priority_down() -> u8 {
    DEFAULT_PRIORITY_DOWN
}

fn default_priority_recovered() -> u8 {
    DEFAULT_PRIORITY_RECOVERED
}

/// One delivery channel: type + parameters. Internally tagged
/// (`"kind": "ntfy"`) so the wire stays self-describing and future
/// variants extend rather than rework it. Priorities keep the M4.1
/// defaults when absent (4 down / 3 recovered).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum DeliveryChannel {
    /// ntfy push, JSON publish form (see `ntfy::send`).
    Ntfy {
        /// Server base URL, e.g. `https://push.example.tld`.
        url: String,
        /// Target topic — a deployment secret, masked in all logs.
        topic: String,
        #[serde(default = "default_priority_down")]
        priority_down: u8,
        #[serde(default = "default_priority_recovered")]
        priority_recovered: u8,
    },
}

/// Versioned channel state as gossiped and cached. `version` is a
/// monotonic counter bumped by the parent node on every change;
/// `channel: None` at `version > 0` means "explicitly cleared"
/// (channel-clear), NOT "unknown" — unknown is `version: 0`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelState {
    pub version: u64,
    #[serde(default)]
    pub channel: Option<DeliveryChannel>,
}

impl ChannelState {
    /// The "know nothing" state: version 0, no channel. Replaced by
    /// the first gossip message or `channel.json` cache load.
    pub fn unknown() -> Self {
        Self { version: 0, channel: None }
    }
}

impl DeliveryChannel {
    /// Materialize this channel into the forwarder's parameter struct
    /// (M4.1 `NtfySection`). Non-ntfy variants of the future return
    /// their own params from their own match arm — the forwarder never
    /// pattern-matches on the enum itself.
    pub fn to_ntfy_params(&self) -> NtfySection {
        match self {
            DeliveryChannel::Ntfy { url, topic, priority_down, priority_recovered } => NtfySection {
                url: url.clone(),
                topic: topic.clone(),
                priority_down: *priority_down,
                priority_recovered: *priority_recovered,
            },
        }
    }
}

/// Apply `incoming` to `dst` ONLY when its version is strictly
/// greater (monotonic forward merge — no LWW by wall clock). Returns
/// whether the state advanced (caller then refreshes the cache).
pub fn merge_channel(dst: &mut ChannelState, incoming: &ChannelState) -> bool {
    if incoming.version > dst.version {
        *dst = incoming.clone();
        true
    } else {
        false
    }
}

/// Effective push channel for THIS node's forwarder: the local
/// `[ntfy]` section always wins (per-node override, e.g. a test node
/// with its own topic), then the network channel, then nothing
/// (feature off — legacy silent path).
pub fn resolve(local: Option<&NtfySection>, network: &ChannelState) -> Option<NtfySection> {
    if let Some(local) = local {
        return Some(local.clone());
    }
    network.channel.as_ref().map(DeliveryChannel::to_ntfy_params)
}

/// The ntfy topic doubles as an access credential: show at most its
/// first 3 chars in any log or status line (same rule as the CLI's
/// mask).
pub fn mask_topic(topic: &str) -> String {
    let mut head: String = topic.chars().take(3).collect();
    if topic.chars().count() > 3 {
        head.push('…');
    }
    head
}

impl ChannelState {
    /// Log-safe one-liner for state transitions: channel type, url,
    /// masked topic. Never leaks the full topic.
    pub fn summary(&self) -> String {
        match &self.channel {
            None => "off".to_string(),
            Some(DeliveryChannel::Ntfy { url, topic, .. }) => {
                format!("ntfy {url} topic {}", mask_topic(topic))
            }
        }
    }
}

/// Deserialize the gossip `channels` field leniently: an undecodable
/// payload (e.g. a future channel `kind` this binary doesn't know)
/// becomes `None` instead of failing the WHOLE gossip message —
/// topology exchange must not break over a channel type. The state is
/// simply ignored until this node is upgraded.
pub fn deserialize_channels_gossip<'de, D>(d: D) -> Result<Option<ChannelState>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Option::<serde_json::Value>::deserialize(d)?;
    match raw {
        None => Ok(None),
        Some(v) => match serde_json::from_value::<ChannelState>(v) {
            Ok(st) => Ok(Some(st)),
            Err(e) => {
                tracing::debug!(error = %e, "ignoring undecodable channel state (unknown kind?)");
                Ok(None)
            }
        },
    }
}

/// Load the `channel.json` cache from `dir`. Missing file = `unknown`
/// (fresh node); unreadable/broken file = `unknown` + warn — the
/// channel then re-arrives via gossip, a broken cache must never keep
/// the node from starting.
pub fn load_cache(dir: &Path) -> ChannelState {
    let path = dir.join(CACHE_FILENAME);
    match std::fs::read_to_string(&path) {
        Ok(text) => match serde_json::from_str::<ChannelState>(&text) {
            Ok(st) => st,
            Err(e) => {
                tracing::warn!(error = %e, path = %path.display(), "channel cache unreadable, starting fresh");
                ChannelState::unknown()
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => ChannelState::unknown(),
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "channel cache read failed, starting fresh");
            ChannelState::unknown()
        }
    }
}

/// Persist `state` to `dir/channel.json` atomically (tmp + rename).
/// Best-effort like every persistence here: failures are logged
/// warns, never fatal — gossip re-delivers the state anyway.
pub fn save_cache(dir: &Path, state: &ChannelState) {
    let path = dir.join(CACHE_FILENAME);
    let tmp = dir.join(format!("{CACHE_FILENAME}.tmp"));
    let write = || -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(state)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(&tmp, json)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    };
    if let Err(e) = write() {
        tracing::warn!(error = %e, path = %path.display(), "channel cache write failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ntfy(topic: &str) -> DeliveryChannel {
        DeliveryChannel::Ntfy {
            url: "http://127.0.0.1:9999".into(),
            topic: topic.into(),
            priority_down: 4,
            priority_recovered: 3,
        }
    }

    fn st(version: u64, topic: &str) -> ChannelState {
        ChannelState { version, channel: (version > 0).then(|| ntfy(topic)) }
    }

    // ---------- merge: monotonic, strictly forward ----------

    #[test]
    fn merge_applies_strictly_greater_version() {
        let mut local = st(1, "test-topic");
        let incoming = st(2, "test-topic-2");
        assert!(merge_channel(&mut local, &incoming), "greater version must apply");
        assert_eq!(local, incoming, "the whole state is replaced, not field-merged");
    }

    #[test]
    fn merge_learns_from_unknown_zero() {
        let mut local = ChannelState::unknown();
        assert!(merge_channel(&mut local, &st(1, "test-topic")));
        assert_eq!(local.version, 1);
    }

    #[test]
    fn merge_ignores_equal_version() {
        let mut local = st(3, "test-topic");
        let incoming = st(3, "test-topic-2");
        assert!(!merge_channel(&mut local, &incoming), "equal version is a no-op");
        assert_eq!(local.channel.unwrap().to_ntfy_params().topic, "test-topic");
    }

    #[test]
    fn merge_ignores_older_version() {
        let mut local = st(5, "test-topic");
        assert!(!merge_channel(&mut local, &st(4, "test-topic-2")), "downgrade ignored");
        assert_eq!(local.version, 5, "out-of-order gossip must not roll back");
    }

    #[test]
    fn merge_ignores_duplicate_delivery() {
        let mut local = st(2, "test-topic");
        let dup = local.clone();
        assert!(!merge_channel(&mut local, &dup), "duplicate delivery is a no-op");
        assert_eq!(local, dup);
    }

    #[test]
    fn merge_clear_beats_channel_at_lower_version() {
        // clear (channel None) at a higher version wins over an older
        // channel-bearing state — "explicitly off" is a real state.
        let mut local = st(2, "test-topic");
        let cleared = ChannelState { version: 3, channel: None };
        assert!(merge_channel(&mut local, &cleared));
        assert_eq!(local.channel, None);
    }

    // ---------- serde / wire shape ----------

    #[test]
    fn serde_roundtrip_internally_tagged() {
        let v = serde_json::to_value(st(2, "test-topic")).unwrap();
        assert_eq!(v["version"], 2);
        assert_eq!(v["channel"]["kind"], "ntfy", "tag name is 'kind'");
        let back: ChannelState = serde_json::from_value(v).unwrap();
        assert_eq!(back, st(2, "test-topic"));
    }

    #[test]
    fn serde_channel_null_roundtrip() {
        let cleared = ChannelState { version: 7, channel: None };
        let back: ChannelState =
            serde_json::from_str(&serde_json::to_string(&cleared).unwrap()).unwrap();
        assert_eq!(back, cleared, "cleared state survives the cache roundtrip");
    }

    #[test]
    fn serde_ntfy_priorities_default() {
        let raw = r#"{"version":1,"channel":{"kind":"ntfy","url":"http://127.0.0.1:9999","topic":"test-topic"}}"#;
        let parsed: ChannelState = serde_json::from_str(raw).unwrap();
        match parsed.channel {
            Some(DeliveryChannel::Ntfy { priority_down, priority_recovered, .. }) => {
                assert_eq!(priority_down, 4, "M4.1 default down priority");
                assert_eq!(priority_recovered, 3, "M4.1 default recovered priority");
            }
            other => panic!("expected ntfy channel, got {other:?}"),
        }
    }

    #[test]
    fn serde_unknown_kind_is_an_error_on_the_enum() {
        // strictness of the enum itself: unknown kind does not decode
        // into a channel — gossip-level tolerance lives in
        // deserialize_channels_gossip (transport tests cover it).
        let raw = r#"{"version":1,"channel":{"kind":"telegram","chat":42}}"#;
        assert!(serde_json::from_str::<ChannelState>(raw).is_err());
    }

    // ---------- resolve: local > network > off ----------

    #[test]
    fn resolve_prefers_local_section() {
        let local = NtfySection {
            url: "http://127.0.0.1:9998".into(),
            topic: "test-topic-local".into(),
            priority_down: 4,
            priority_recovered: 3,
        };
        let got = resolve(Some(&local), &st(5, "test-topic-net")).unwrap();
        assert_eq!(got.topic, "test-topic-local", "local [ntfy] overrides the network channel");
    }

    #[test]
    fn resolve_falls_back_to_network_channel() {
        let got = resolve(None, &st(5, "test-topic-net")).unwrap();
        assert_eq!(got.url, "http://127.0.0.1:9999");
        assert_eq!(got.topic, "test-topic-net");
        assert_eq!(got.priority_down, 4);
        assert_eq!(got.priority_recovered, 3);
    }

    #[test]
    fn resolve_none_when_no_local_and_no_network_channel() {
        assert_eq!(resolve(None, &ChannelState::unknown()), None);
        assert_eq!(
            resolve(None, &ChannelState { version: 9, channel: None }),
            None,
            "cleared network state is off, not a fallback error"
        );
    }

    #[test]
    fn to_ntfy_params_maps_every_field() {
        let p = ntfy("test-topic").to_ntfy_params();
        assert_eq!(p.url, "http://127.0.0.1:9999");
        assert_eq!(p.topic, "test-topic");
        assert_eq!(p.priority_down, 4);
        assert_eq!(p.priority_recovered, 3);
    }

    // ---------- masking / summaries ----------

    #[test]
    fn mask_topic_keeps_first_three_chars_only() {
        assert_eq!(mask_topic("topsecret-topic-9"), "top…");
        assert_eq!(mask_topic("abc"), "abc");
        assert_eq!(mask_topic(""), "");
    }

    #[test]
    fn summary_never_leaks_the_topic() {
        let s = st(2, "topsecret-topic-9").summary();
        assert!(s.contains("top…"), "summary masks the topic: {s}");
        assert!(!s.contains("topsecret"), "full topic must not appear: {s}");
        assert_eq!(ChannelState { version: 5, channel: None }.summary(), "off");
    }

    // ---------- cache file ----------

    #[test]
    fn cache_roundtrip_and_missing_file() {
        let dir = std::env::temp_dir().join("em-channel-cache-test");
        std::fs::create_dir_all(&dir).unwrap();
        let _ = std::fs::remove_file(dir.join(CACHE_FILENAME));

        assert_eq!(load_cache(&dir), ChannelState::unknown(), "missing file = unknown");

        let state = st(4, "test-topic");
        save_cache(&dir, &state);
        assert_eq!(load_cache(&dir), state, "cache survives save/load");
        assert!(!dir.join(format!("{CACHE_FILENAME}.tmp")).exists(), "tmp file renamed away");
    }

    #[test]
    fn broken_cache_file_is_ignored_without_panic() {
        let dir = std::env::temp_dir().join("em-channel-cache-broken-test");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(CACHE_FILENAME), "{not json at all").unwrap();
        assert_eq!(load_cache(&dir), ChannelState::unknown(), "broken json = fresh start");
    }
}
