//! M3.7: flap-guarded event history.
//!
//! The mesh already collects raw observations (site probes, ssh matrix,
//! gossip evidence, systemd units) but until now each failure meant a
//! fresh warn line every round — the "flapping" pain this module kills.
//! Instead of raw probes, [`FlapTracker`] keeps a tiny per-target state
//! machine and emits an [`Event`] only on CONFIRMED state transitions:
//!
//! * the first observation of a target is a baseline — no event (anti-storm
//!   when a node boots and learns about a dozen targets at once);
//! * `down` fires on the N-th CONSECUTIVE failure (N = flap_fail_threshold,
//!   default 3), never on the first hiccup;
//! * `recovered` fires on the first success after a confirmed `down`;
//! * while a target is down, further failures stay silent (one transition,
//!   not a warn per round).
//!
//! Events are append-only JSONL (`logs/events.jsonl`, one JSON object per
//! line, size-rotated exactly like the daemon logs) and never travel over
//! the wire: each node records only its OWN observations ("site:X down"
//! means "as seen from here"). Cross-node consolidation is M4.5 work on
//! the parent, deliberately out of scope here.
//!
//! Zero new dependencies: std::fs + serde/serde_json + tracing, all
//! already in the tree.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};

/// Rotation threshold for `events.jsonl` — same 10 MiB per file as
/// `logging::MAX_LOG_BYTES` (one rotated generation `.1`, then reuse).
/// Events are rare (state transitions only), so this is a lifetime cap
/// in practice, not a churn knob.
pub const EVENTS_MAX_BYTES: u64 = 10 * 1024 * 1024;

// ---------- event ----------

/// What happened to a target. Serialized snake_case (`"down"` /
/// `"recovered"`) — the wire format of events.jsonl is read by humans,
/// `status` and M4.5 report tooling, so it is part of the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventChange {
    Down,
    Recovered,
}

/// One confirmed state transition of one target, as observed by THIS node.
/// Target naming convention (see M3.7-b wiring): `site:<check_id>`,
/// `ssh:<from>-><to>`, `node:<id>`, `unit:<name>`.
///
/// `detail` is an optional human hint (e.g. the ssh failure reason or the
/// HTTP status); it serializes as `null` when unknown — the key is always
/// present so the JSONL schema is stable line to line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Unix epoch milliseconds, same clock as gossip evidence and probes.
    pub at_ms: u64,
    pub target: String,
    pub change: EventChange,
    pub detail: Option<String>,
}

// ---------- flap tracker ----------

/// Per-target flap state. `up: None` until the first observation; after
/// that `Some(true)` = believed up, `Some(false)` = confirmed down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetState {
    pub up: Option<bool>,
    /// Consecutive failures while believed up. Held at the threshold once
    /// down (so a look at the state tells "how bad" without re-counting).
    pub fails: u32,
}

/// Hysteresis automaton, one [`TargetState`] per target string. The
/// semantic sibling of `elector::StabilityGate`: a change must hold for
/// N consecutive observations before it is believed, which is exactly the
/// "down is confirmed by N failures in a row, not the first miss" rule
/// from the M3.7 roadmap.
pub struct FlapTracker {
    /// N consecutive failures required to flip up -> down. Clamped to >= 1
    /// at construction (0 would mean "down on the first miss", i.e. no
    /// flap protection at all — a misconfiguration, not a mode).
    threshold: u32,
    states: HashMap<String, TargetState>,
}

impl FlapTracker {
    pub fn new(threshold: u32) -> Self {
        Self { threshold: threshold.max(1), states: HashMap::new() }
    }

    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    /// Record one observation of `target` and return the state-transition
    /// event, if any. Pure function of the observation stream: same calls
    /// in the same order give the same events, which is what makes the
    /// tracker unit-testable without sockets, timers or the daemon.
    ///
    /// Baseline subtlety: a FAILING first observation seeds the target as
    /// believed-up and counts as consecutive failure #1. A target that is
    /// dead from the node's own boot therefore still reaches `down` after
    /// N total consecutive failures (the event for the first observation is
    /// suppressed, the counting is not) — otherwise "down since forever"
    /// could never alert at all.
    pub fn observe(
        &mut self,
        target: &str,
        ok: bool,
        at_ms: u64,
        detail: Option<&str>,
    ) -> Option<Event> {
        let st = self
            .states
            .entry(target.to_string())
            .or_insert(TargetState { up: None, fails: 0 });

        // First sighting: baseline only, no event (anti-storm at boot).
        if st.up.is_none() {
            *st = TargetState { up: Some(true), fails: u32::from(!ok) };
            return None;
        }

        let believed_up = st.up.unwrap();
        // Observation agrees with the believed state: nothing to announce.
        // A SUCCESS while up also resets the failure streak (the actual
        // flap guard); a fail while down leaves the streak pinned at the
        // threshold — it records "what it took to go down" and is reset
        // only by recovery.
        if ok == believed_up {
            if believed_up {
                st.fails = 0;
            }
            return None;
        }

        if ok {
            // Success after confirmed down: immediate recovery — no
            // symmetric N-successes requirement, because a working probe
            // is itself strong evidence (the failure reason, by contrast,
            // may be transient network weather).
            st.up = Some(true);
            st.fails = 0;
            return Some(self.event(target, at_ms, EventChange::Recovered, detail));
        }

        // Failure while believed up: count it, fire only on the Nth streak.
        st.fails += 1;
        if st.fails >= self.threshold {
            st.up = Some(false);
            st.fails = self.threshold;
            return Some(self.event(target, at_ms, EventChange::Down, detail));
        }
        None
    }

    fn event(
        &self,
        target: &str,
        at_ms: u64,
        change: EventChange,
        detail: Option<&str>,
    ) -> Event {
        Event {
            at_ms,
            target: target.to_string(),
            change,
            detail: detail.map(str::to_string),
        }
    }
}

// ---------- jsonl log ----------

/// Append-only JSONL sink with size rotation — a faithful copy of the
/// `logging::SizeRotatingWriter` scheme, minus the tracing plumbing:
/// events are rare, so the file is opened per append instead of being
/// held open (same precedent as `checks::History::push`).
pub struct EventLog {
    path: PathBuf,
    max_bytes: u64,
    /// Append failures warn exactly once per log lifetime: a broken path
    /// (read-only dir, removed mount) would otherwise re-warn on every
    /// event forever, which is the noise this module exists to remove.
    warned: AtomicBool,
}

impl EventLog {
    pub fn new(path: PathBuf) -> Self {
        Self { path, max_bytes: EVENTS_MAX_BYTES, warned: AtomicBool::new(false) }
    }

    /// Test/sealed-deployment variant with a custom rotation threshold
    /// (the unit tests rotate with a handful of bytes, not 10 MiB).
    pub fn with_max_bytes(path: PathBuf, max_bytes: u64) -> Self {
        Self { path, max_bytes, warned: AtomicBool::new(false) }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Write one event as one JSON line. Never panics and never fails the
    /// caller: monitoring must not die because a log directory went away.
    pub fn append(&self, ev: &Event) {
        self.rotate_if_needed();
        let line = serde_json::to_string(ev).unwrap_or_default();
        let res = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .and_then(|mut f| writeln!(f, "{line}"));
        if let Err(e) = res {
            if !self.warned.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    path = %self.path.display(),
                    error = %e,
                    "events.jsonl append failed (staying silent on further failures)"
                );
            }
        }
    }

    /// Same rotation as logging.rs: once the file has outgrown the limit,
    /// move it aside as `.1` (one generation, previous `.1` is replaced).
    fn rotate_if_needed(&self) {
        if let Ok(md) = std::fs::metadata(&self.path) {
            if md.len() >= self.max_bytes {
                let mut rotated = self.path.clone().into_os_string();
                rotated.push(".1");
                let _ = std::fs::rename(&self.path, rotated);
            }
        }
    }
}

// ---------- recorder ----------

/// The piece everything else talks to: flap tracking + optional JSONL
/// persistence + tracing lines, one call per raw observation.
///
/// Deliberately sync (`&mut self`, no async): the M3.7-b wiring keeps a
/// std Mutex over it and takes care to never hold that guard across an
/// await — observe() does file I/O on an already-open-per-append basis
/// and returns immediately.
pub struct EventRecorder {
    tracker: FlapTracker,
    log: Option<EventLog>,
}

impl EventRecorder {
    /// In-memory recorder; attach the file sink later with [`Self::set_log`]
    /// (tests and any file-less embedding never call it).
    pub fn new(threshold: u32) -> Self {
        Self { tracker: FlapTracker::new(threshold), log: None }
    }

    pub fn set_log(&mut self, path: PathBuf) {
        self.log = Some(EventLog::new(path));
    }

    pub fn threshold(&self) -> u32 {
        self.tracker.threshold()
    }

    /// Observe one raw result for `target`: track the transition, persist
    /// and log it if there is one. Returns the event for callers that
    /// need it (tests, future alert channels in M4); `None` when the
    /// observation changed nothing.
    pub fn observe(
        &mut self,
        target: &str,
        ok: bool,
        at_ms: u64,
        detail: Option<&str>,
    ) -> Option<Event> {
        let ev = self.tracker.observe(target, ok, at_ms, detail)?;
        if let Some(log) = &self.log {
            log.append(&ev);
        }
        // The daemon log noise budget: down = warn (operator should look),
        // recovered = info (closure, not a new fire). This replaces the
        // per-round repeated warns of the pre-M3.7 loops.
        match ev.change {
            EventChange::Down => tracing::warn!(
                target = %ev.target,
                detail = ev.detail.as_deref(),
                "confirmed down"
            ),
            EventChange::Recovered => tracing::info!(
                target = %ev.target,
                detail = ev.detail.as_deref(),
                "recovered"
            ),
        }
        Some(ev)
    }
}

/// Liveness adapter: fold peer evidence (node id -> unix ms of the last
/// successful contact, see `transport::NodeState::evidence`) into the
/// recorder as `node:<id>` observations. Called from the gossip loop
/// after each round (M3.7-b).
///
/// Two deliberate silences, per the M3.7 plan:
/// * a peer with NO evidence record is skipped — "never contacted" is
///   indistinguishable from "dead since birth", and the honest signal is
///   "seen alive, then went away";
/// * self is skipped — a node records only its own observations about
///   others, never about itself (its own liveness is everyone else's job).
pub fn observe_liveness(
    recorder: &mut EventRecorder,
    self_id: u32,
    known_nodes: &[u32],
    evidence: &HashMap<u32, u64>,
    now_ms: u64,
    t_dead_ms: u64,
) {
    // Deterministic order regardless of config order: observation streams
    // feed a state machine, and unstable ordering would make behavior
    // (and tests) depend on HashMap/config luck.
    let mut ids: Vec<u32> = known_nodes.iter().copied().filter(|id| *id != self_id).collect();
    ids.sort_unstable();
    ids.dedup();
    for id in ids {
        let Some(&last_seen) = evidence.get(&id) else { continue };
        let ok = now_ms.saturating_sub(last_seen) < t_dead_ms;
        recorder.observe(&format!("node:{id}"), ok, now_ms, None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fresh tempdir per test (parallel tests would collide otherwise);
    /// same convention as the docker.rs suite.
    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("em-m37a-events-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn change_of(ev: &Option<Event>) -> EventChange {
        ev.as_ref().map(|e| e.change).unwrap()
    }

    // ---- FlapTracker semantics ----

    #[test]
    fn baseline_first_observation_is_silent() {
        // Both a healthy and a failing first sighting just seed the state:
        // no events, whatever the direction (anti-storm at node boot).
        let mut t = FlapTracker::new(3);
        assert_eq!(t.observe("site:x", true, 1, None), None);
        assert_eq!(t.observe("site:y", false, 1, None), None);
        assert_eq!(t.states["site:x"], TargetState { up: Some(true), fails: 0 });
        // Failing baseline counts as streak failure #1 (dead-from-boot
        // targets must still be able to reach the threshold).
        assert_eq!(t.states["site:y"], TargetState { up: Some(true), fails: 1 });
    }

    #[test]
    fn down_fires_on_nth_consecutive_fail_only() {
        // The hysteresis border: threshold-1 consecutive fails stay silent,
        // the threshold-th one flips the state and fires.
        let mut t = FlapTracker::new(3);
        t.observe("site:x", true, 1, None); // baseline up
        assert_eq!(t.observe("site:x", false, 2, None), None); // fail #1
        assert_eq!(t.observe("site:x", false, 3, None), None); // fail #2
        let ev = t.observe("site:x", false, 4, Some("conn refused")).unwrap(); // fail #3
        assert_eq!(ev.change, EventChange::Down);
        assert_eq!(ev.target, "site:x");
        assert_eq!(ev.at_ms, 4);
        assert_eq!(ev.detail.as_deref(), Some("conn refused"));
        // State after: confirmed down, streak pinned at threshold.
        assert_eq!(t.states["site:x"], TargetState { up: Some(false), fails: 3 });
    }

    #[test]
    fn success_between_fails_resets_streak() {
        // The core flap guard: fail-ok-fail-fail never reaches threshold 3.
        let mut t = FlapTracker::new(3);
        t.observe("site:x", true, 1, None);
        assert_eq!(t.observe("site:x", false, 2, None), None);
        assert_eq!(t.observe("site:x", true, 3, None), None); // streak reset
        assert_eq!(t.observe("site:x", false, 4, None), None); // streak #1
        assert_eq!(t.observe("site:x", false, 5, None), None); // streak #2
        assert_eq!(t.states["site:x"].fails, 2);
    }

    #[test]
    fn fail_while_down_stays_silent() {
        // One transition, not a warn per round: while down, more fails
        // produce nothing.
        let mut t = FlapTracker::new(2);
        t.observe("site:x", true, 1, None);
        t.observe("site:x", false, 2, None);
        t.observe("site:x", false, 3, None).unwrap(); // down
        assert_eq!(t.observe("site:x", false, 4, None), None);
        assert_eq!(t.observe("site:x", false, 5, None), None);
        assert_eq!(t.states["site:x"].fails, 2); // pinned at threshold
    }

    #[test]
    fn first_success_after_down_recovers() {
        let mut t = FlapTracker::new(2);
        t.observe("site:x", true, 1, None);
        t.observe("site:x", false, 2, None);
        t.observe("site:x", false, 3, None).unwrap(); // down
        assert_eq!(t.observe("site:x", false, 4, None), None);
        let ev = t.observe("site:x", true, 5, None).unwrap();
        assert_eq!(ev.change, EventChange::Recovered);
        assert_eq!(ev.at_ms, 5);
        assert_eq!(t.states["site:x"], TargetState { up: Some(true), fails: 0 });
        // And a following ok is silent again (agrees with state).
        assert_eq!(t.observe("site:x", true, 6, None), None);
    }

    #[test]
    fn threshold_zero_clamps_to_one() {
        // 0 would mean "alert on the first miss" — no protection at all;
        // treated as misconfiguration and clamped to 1.
        let mut t = FlapTracker::new(0);
        assert_eq!(t.threshold(), 1);
        t.observe("site:x", true, 1, None); // healthy baseline
        // With threshold 1 the first fail after an up state is already
        // the Nth consecutive: fires immediately (still not on baseline).
        assert_eq!(change_of(&t.observe("site:x", false, 2, None)), EventChange::Down);
        // A FAILING baseline stays silent (no event for the first sighting)
        // but counts as streak #1, so the very next fail fires too.
        let mut t2 = FlapTracker::new(0);
        assert_eq!(t2.observe("site:y", false, 1, None), None);
        assert_eq!(change_of(&t2.observe("site:y", false, 2, None)), EventChange::Down);
    }

    #[test]
    fn targets_are_independent() {
        // Site checks observe many targets through one tracker; a failing
        // streak of one must not leak into another's state.
        let mut t = FlapTracker::new(2);
        t.observe("site:a", true, 1, None);
        t.observe("site:b", true, 1, None);
        t.observe("site:a", false, 2, None);
        t.observe("site:a", false, 3, None).unwrap(); // a down
        assert_eq!(t.observe("site:b", false, 4, None), None); // b streak #1
        assert_eq!(t.states["site:b"].up, Some(true));
    }

    // ---- Event serde contract ----

    #[test]
    fn event_jsonl_line_roundtrips() {
        // The exact JSONL contract: one line, detail always present
        // (null when unknown), change snake_case.
        let ev = Event {
            at_ms: 1_768_400_000_000,
            target: "site:importmath".into(),
            change: EventChange::Down,
            detail: Some("HTTP 500".into()),
        };
        let line = serde_json::to_string(&ev).unwrap();
        assert_eq!(
            line,
            "{\"at_ms\":1768400000000,\"target\":\"site:importmath\",\"change\":\"down\",\"detail\":\"HTTP 500\"}"
        );
        assert_eq!(serde_json::from_str::<Event>(&line).unwrap(), ev);

        let ev2 = Event { detail: None, ..ev };
        assert_eq!(
            serde_json::to_string(&ev2).unwrap(),
            "{\"at_ms\":1768400000000,\"target\":\"site:importmath\",\"change\":\"down\",\"detail\":null}"
        );
        assert_eq!(serde_json::from_str::<Event>(&serde_json::to_string(&ev2).unwrap()).unwrap(), ev2);
        // And the recovered spelling, since it is part of the schema.
        assert!(serde_json::to_string(&EventChange::Recovered).unwrap().contains("recovered"));
    }

    // ---- EventLog ----

    #[test]
    fn event_log_appends_one_json_line_per_event() {
        let d = tmp("append");
        let log = EventLog::new(d.join("events.jsonl"));
        log.append(&Event {
            at_ms: 7,
            target: "unit:echoeye".into(),
            change: EventChange::Down,
            detail: None,
        });
        log.append(&Event {
            at_ms: 9,
            target: "unit:echoeye".into(),
            change: EventChange::Recovered,
            detail: None,
        });
        let raw = std::fs::read_to_string(d.join("events.jsonl")).unwrap();
        let lines: Vec<&str> = raw.lines().collect();
        assert_eq!(lines.len(), 2);
        let first: Event = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first.target, "unit:echoeye");
        assert_eq!(first.change, EventChange::Down);
        assert_eq!(first.at_ms, 7);
        assert_eq!(serde_json::from_str::<Event>(lines[1]).unwrap().change, EventChange::Recovered);
    }

    #[test]
    fn event_log_rotates_at_limit() {
        let d = tmp("rotate");
        let path = d.join("events.jsonl");
        // Seed a file already at/over the tiny limit, then append: the old
        // content must move to .1 and the new line land in a fresh file.
        std::fs::write(&path, vec![b'x'; 64]).unwrap();
        let log = EventLog::with_max_bytes(path.clone(), 64);
        log.append(&Event {
            at_ms: 1,
            target: "site:x".into(),
            change: EventChange::Down,
            detail: None,
        });
        assert!(d.join("events.jsonl.1").exists());
        assert_eq!(std::fs::metadata(d.join("events.jsonl.1")).unwrap().len(), 64);
        let fresh = std::fs::read_to_string(&path).unwrap();
        assert_eq!(fresh.lines().count(), 1);
        assert!(fresh.contains("\"change\":\"down\""));
    }

    #[test]
    fn event_log_never_panics_on_unwritable_path() {
        // A file sink pointed at a directory-that-is-a-file: open fails,
        // append must swallow the error (monitoring outlives its logs).
        let d = tmp("broken");
        let not_a_dir = d.join("occupied");
        std::fs::write(&not_a_dir, b"").unwrap();
        let log = EventLog::new(not_a_dir.join("nested").join("events.jsonl"));
        log.append(&Event {
            at_ms: 1,
            target: "site:x".into(),
            change: EventChange::Down,
            detail: None,
        });
        // Missing (parent) directory: also silent and non-fatal.
        let log2 = EventLog::new(d.join("no").join("such").join("dir").join("events.jsonl"));
        log2.append(&Event {
            at_ms: 2,
            target: "site:x".into(),
            change: EventChange::Recovered,
            detail: None,
        });
    }

    // ---- EventRecorder ----

    #[test]
    fn recorder_persists_transitions_to_jsonl() {
        let d = tmp("recorder");
        let mut r = EventRecorder::new(2);
        // In-memory phase: transitions tracked, nothing on disk anywhere.
        r.observe("ssh:1->2", true, 1, None);
        r.observe("ssh:1->2", false, 2, Some("refused"));
        assert_eq!(r.observe("ssh:1->2", false, 3, Some("refused")).unwrap().change, EventChange::Down);
        assert_eq!(r.threshold(), 2);
        // Attach the sink mid-life: later transitions land in the file,
        // earlier ones do not retroactively.
        r.set_log(d.join("events.jsonl"));
        let ev = r.observe("ssh:1->2", true, 4, None).unwrap();
        assert_eq!(ev.change, EventChange::Recovered);
        assert_eq!(ev.detail, None);
        let raw = std::fs::read_to_string(d.join("events.jsonl")).unwrap();
        assert_eq!(raw.lines().count(), 1);
        let parsed: Event = serde_json::from_str(raw.trim()).unwrap();
        assert_eq!(parsed.change, EventChange::Recovered);
        assert_eq!(parsed.target, "ssh:1->2");
        assert_eq!(parsed.detail, None);
    }

    // ---- liveness adapter ----

    #[test]
    fn liveness_fresh_ok_stale_fires_down_then_recovered() {
        // Full arc through the adapter, captured via the JSONL sink (the
        // adapter itself returns nothing — its contract is the event file).
        let d = tmp("liveness");
        let mut r = EventRecorder::new(3);
        r.set_log(d.join("events.jsonl"));

        // Round 1 (now=2000, t_dead=3000): nodes 2 and 3 both fresh
        // (last seen at t=1000) -> baselines, file stays empty.
        let evidence = HashMap::from([(2u32, 1_000u64), (3u32, 1_000u64)]);
        observe_liveness(&mut r, 1, &[1, 2, 3], &evidence, 2_000, 3_000);
        assert!(!d.join("events.jsonl").exists());

        // Node 2 gets fresh evidence, node 3 goes stale from here on.
        let mut stale = evidence.clone();
        stale.insert(2, 4_000);
        observe_liveness(&mut r, 1, &[1, 2, 3], &stale, 4_200, 3_000); // node 3: fail #1
        observe_liveness(&mut r, 1, &[1, 2, 3], &stale, 4_300, 3_000); // fail #2
        observe_liveness(&mut r, 1, &[1, 2, 3], &stale, 4_400, 3_000); // fail #3 -> DOWN
        let raw = std::fs::read_to_string(d.join("events.jsonl")).unwrap();
        assert_eq!(raw.lines().count(), 1);
        let down: Event = serde_json::from_str(raw.lines().next().unwrap()).unwrap();
        assert_eq!((down.target.as_str(), down.change), ("node:3", EventChange::Down));

        // Node 3's evidence refreshes -> first fresh round -> RECOVERED.
        let mut fresh = stale.clone();
        fresh.insert(3, 4_600);
        observe_liveness(&mut r, 1, &[1, 2, 3], &fresh, 4_700, 3_000);
        let raw = std::fs::read_to_string(d.join("events.jsonl")).unwrap();
        assert_eq!(raw.lines().count(), 2);
        let rec: Event = serde_json::from_str(raw.lines().last().unwrap()).unwrap();
        assert_eq!((rec.target.as_str(), rec.change), ("node:3", EventChange::Recovered));

        // Node 2 stayed fresh the whole time, self (1) is never observed:
        // no other targets ever appear in the file.
        assert!(raw.lines().all(|l| l.contains("node:3")));
    }

    #[test]
    fn liveness_skips_unseen_and_self() {
        let mut r = EventRecorder::new(3);
        let evidence: HashMap<u32, u64> = HashMap::from([(2u32, 1_000u64)]);
        // Node 4 configured but never contacted (no evidence record),
        // node 1 is self: neither may produce any observation.
        observe_liveness(&mut r, 1, &[1, 2, 4], &evidence, 10_000_000, 3_000);
        assert_eq!(r.tracker.states.len(), 1);
        assert!(r.tracker.states.contains_key("node:2"));
        // Node 2, one stale round: still just a streak, no event.
        assert_eq!(r.tracker.states["node:2"].fails, 1);
    }
}
