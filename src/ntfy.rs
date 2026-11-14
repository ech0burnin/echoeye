//! M4.1: ntfy push notifications for confirmed events.
//!
//! The event tap lives in [`crate::events::EventRecorder`]: every
//! confirmed transition (`down`/`recovered`) is fanned out to subscriber
//! channels, and [`spawn_forwarder`] turns that stream into one ntfy
//! push per event. Deliberately thin and sequential:
//!
//! * one push per confirmed transition — the flap tracker upstream
//!   (M3.7) is already the rate limiter, no batching or retry here;
//! * a failed push is a `warn`, never a crash: events.jsonl already
//!   holds the durable record, the push channel is best-effort;
//! * sequential sends give natural backpressure against a slow ntfy
//!   server (rare events + 5s timeout cannot pile up meaningfully).
//!
//! Publishing uses the ntfy JSON form: `POST {url}/{topic}` with
//! `{"topic","title","message","priority","tags"}` (the `topic` field
//! repeats the path segment — both spell the same destination, and the
//! JSON body keeps the payload self-describing in captures/logs).
//!
//! Zero new dependencies: reqwest (json + rustls-tls) and tokio are
//! already in the tree for gossip and probes.

use crate::events::{Event, EventChange};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::sync::mpsc::UnboundedReceiver;

/// Push priority for confirmed `down` transitions (ntfy scale 0-5).
/// 4 = "high" in the ntfy/Android vocabulary — urgent without the
/// P5 alarm-clock behavior (a monitoring push must not require a
/// manual acknowledgement to stop ringing).
pub const DEFAULT_PRIORITY_DOWN: u8 = 4;
/// Push priority for `recovered` transitions: 3 = default urgency,
/// closure is information, not a fire.
pub const DEFAULT_PRIORITY_RECOVERED: u8 = 3;
/// Per-request budget. Pushes are non-critical telemetry: a dead ntfy
/// server must not stall the forwarder queue for long (same order as
/// the gossip client timeout, generous for a slow phone-hop link).
pub const SEND_TIMEOUT_SECS: u64 = 5;
/// Body cap: site details can be long error chains (see the M3.7 smoke)
/// — a push body must stay glanceable. Precedent: docker/sshmatrix
/// snippets, just a wider budget for the notification shade.
pub const BODY_MAX_CHARS: usize = 120;

fn default_priority_down() -> u8 {
    DEFAULT_PRIORITY_DOWN
}

fn default_priority_recovered() -> u8 {
    DEFAULT_PRIORITY_RECOVERED
}

/// `[ntfy]` section of network.toml — per-node push channel config.
/// Lives here (not in config.rs) following the `HttpCheckSpec` precedent:
/// the section struct ships next to the code that consumes it.
///
/// Deliberately NOT replicated by gossip (adopt/union_merge carry only
/// nodes+edges) and NOT part of the admin hash: like the `net.*` knobs
/// this is local-node tuning — each operator decides whether THIS node
/// pushes, and to which topic. Absent section = feature off, bit-for-bit
/// legacy configs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NtfySection {
    /// Server base URL, e.g. `https://push.example.tld` (no trailing
    /// slash needed — normalized in [`endpoint`]).
    pub url: String,
    /// Target topic. Treated as a secret of the deployment: never
    /// echoed into logs verbatim (the ntfy-test CLI masks it).
    pub topic: String,
    #[serde(default = "default_priority_down")]
    pub priority_down: u8,
    #[serde(default = "default_priority_recovered")]
    pub priority_recovered: u8,
}

/// Join a base URL and topic into the publish endpoint, tolerating a
/// trailing slash in the configured url.
pub fn endpoint(url: &str, topic: &str) -> String {
    format!("{}/{}", url.trim_end_matches('/'), topic)
}

/// Push title: `echoeye <node>: <DOWN|RECOVERED> <target>`. The node
/// name makes pushes from different mesh nodes distinguishable when
/// several nodes watch the same site (each pushes its own observation,
/// consolidation is M4.5).
pub fn title_for(ev: &Event, node: &str) -> String {
    let what = match ev.change {
        EventChange::Down => "DOWN",
        EventChange::Recovered => "RECOVERED",
    };
    format!("echoeye {node}: {what} {}", ev.target)
}

/// Push body: the event detail (or an explicit placeholder), truncated
/// to [`BODY_MAX_CHARS`] chars on a char boundary with an ellipsis.
pub fn body_for(ev: &Event) -> String {
    let raw = ev.detail.as_deref().unwrap_or("(no detail)");
    if raw.chars().count() <= BODY_MAX_CHARS {
        raw.to_string()
    } else {
        let cut: String = raw.chars().take(BODY_MAX_CHARS).collect();
        format!("{cut}…")
    }
}

/// Icon tag per transition: red siren for down, green circle for
/// recovered — matching the ntfy emoji-tag conventions.
pub fn tags_for(ev: &Event) -> &'static [&'static str] {
    match ev.change {
        EventChange::Down => &["rotating_light"],
        EventChange::Recovered => &["large_green_circle"],
    }
}

/// JSON publish body (ntfy "publish as JSON" form).
#[derive(Serialize)]
struct NtfyJson<'a> {
    topic: &'a str,
    title: &'a str,
    message: &'a str,
    priority: u8,
    tags: &'a [&'a str],
}

/// One shared client for all pushes of a forwarder (connection reuse
/// across events; each push still bounded by [`SEND_TIMEOUT_SECS`]).
pub fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(SEND_TIMEOUT_SECS))
        .build()
        .expect("reqwest client")
}

/// POST one notification as JSON to `{url}/{topic}`. Any transport
/// error or non-2xx status is an `Err` for the caller to warn about —
/// send never panics, the channel must not take the node down.
pub async fn send(
    client: &reqwest::Client,
    url: &str,
    topic: &str,
    priority: u8,
    title: &str,
    body: &str,
    tags: &[&str],
) -> Result<()> {
    let payload = NtfyJson { topic, title, message: body, priority, tags };
    let resp = client
        .post(endpoint(url, topic))
        .json(&payload)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("ntfy POST to {url} failed: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("ntfy push rejected with HTTP {status}");
    }
    Ok(())
}

/// Drain the recorder's event tap and push every confirmed transition:
/// format → one POST → warn on failure and move on. No retry (the
/// event is already durable in events.jsonl; a stale push after a long
/// outage is noise, not value). The task ends when the recorder side
/// drops (daemon shutdown).
pub fn spawn_forwarder(
    mut rx: UnboundedReceiver<Event>,
    cfg: NtfySection,
    node_name: String,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let http = client();
        while let Some(ev) = rx.recv().await {
            let priority = match ev.change {
                EventChange::Down => cfg.priority_down,
                EventChange::Recovered => cfg.priority_recovered,
            };
            let res = send(
                &http,
                &cfg.url,
                &cfg.topic,
                priority,
                &title_for(&ev, &node_name),
                &body_for(&ev),
                tags_for(&ev),
            )
            .await;
            if let Err(e) = res {
                tracing::warn!(
                    target = %ev.target,
                    error = %e,
                    "ntfy push failed (event is already recorded in events.jsonl)"
                );
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{Event, EventChange};
    use std::sync::{Arc, Mutex};

    fn ev(change: EventChange, target: &str, detail: Option<&str>) -> Event {
        Event {
            at_ms: 1_768_400_000_000,
            target: target.into(),
            change,
            detail: detail.map(str::to_string),
        }
    }

    // ---- formatting ----

    #[test]
    fn title_carries_node_and_direction() {
        let down = ev(EventChange::Down, "site:importmath", Some("HTTP 500"));
        assert_eq!(title_for(&down, "d1337"), "echoeye d1337: DOWN site:importmath");
        let rec = ev(EventChange::Recovered, "node:2", None);
        assert_eq!(title_for(&rec, "vps2"), "echoeye vps2: RECOVERED node:2");
    }

    #[test]
    fn body_is_detail_or_placeholder() {
        assert_eq!(body_for(&ev(EventChange::Down, "site:x", Some("conn refused"))), "conn refused");
        assert_eq!(body_for(&ev(EventChange::Recovered, "site:x", None)), "(no detail)");
    }

    #[test]
    fn body_truncates_long_details_with_ellipsis() {
        let long = "e".repeat(500);
        let out = body_for(&ev(EventChange::Down, "site:x", Some(&long)));
        assert_eq!(out.chars().count(), BODY_MAX_CHARS + 1); // + ellipsis
        assert!(out.ends_with('…'));
        // Exactly at the cap: no truncation, no ellipsis.
        let edge = "y".repeat(BODY_MAX_CHARS);
        assert_eq!(body_for(&ev(EventChange::Down, "site:x", Some(&edge))), edge);
        // Char-boundary safety: multi-byte runes are not chopped mid-codepoint.
        let runes = "ж".repeat(200);
        let out = body_for(&ev(EventChange::Down, "site:x", Some(&runes)));
        assert!(out.chars().all(|c| c == 'ж' || c == '…'));
    }

    #[test]
    fn endpoint_normalizes_trailing_slash() {
        assert_eq!(endpoint("https://push.example.tld", "t1"), "https://push.example.tld/t1");
        assert_eq!(endpoint("http://127.0.0.1:8888/", "t2"), "http://127.0.0.1:8888/t2");
        assert_eq!(endpoint("http://127.0.0.1:8888//", "t3"), "http://127.0.0.1:8888/t3");
    }

    #[test]
    fn tags_follow_direction() {
        assert_eq!(tags_for(&ev(EventChange::Down, "site:x", None)), &["rotating_light"]);
        assert_eq!(
            tags_for(&ev(EventChange::Recovered, "site:x", None)),
            &["large_green_circle"]
        );
    }

    // ---- send against a fake ntfy (real axum on loopback) ----

    /// What the fake ntfy captured: request path + decoded JSON body.
    #[derive(Debug, Clone)]
    struct Captured {
        path: String,
        json: serde_json::Value,
    }

    async fn spawn_fake_ntfy(status: axum::http::StatusCode) -> (u16, Arc<Mutex<Vec<Captured>>>) {
        let sink: Arc<Mutex<Vec<Captured>>> = Arc::new(Mutex::new(Vec::new()));
        let sink_route = sink.clone();
        let routes = axum::Router::new().route(
            "/test-topic",
            axum::routing::post(move |uri: axum::http::Uri, body: String| {
                let sink = sink_route.clone();
                async move {
                    sink.lock().unwrap().push(Captured {
                        path: uri.path().to_string(),
                        json: serde_json::from_str(&body).unwrap_or(serde_json::Value::Null),
                    });
                    status
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, routes).await.unwrap() });
        (port, sink)
    }

    fn fake_cfg(port: u16) -> NtfySection {
        NtfySection {
            url: format!("http://127.0.0.1:{port}"),
            topic: "test-topic".into(),
            priority_down: 4,
            priority_recovered: 3,
        }
    }

    /// Poll with an ASYNC sleep: the forwarder task lives on the same
    /// (current-thread) test runtime, so a blocking std sleep here
    /// would starve it — yield instead between checks.
    async fn wait_for<F: Fn() -> bool>(cond: F) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !cond() {
            assert!(std::time::Instant::now() < deadline, "condition not met within 10s");
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    #[tokio::test]
    async fn send_posts_json_to_topic_endpoint() {
        let (port, sink) = spawn_fake_ntfy(axum::http::StatusCode::OK).await;
        let cfg = fake_cfg(port);
        let client = client();
        send(&client, &cfg.url, &cfg.topic, 4, "echoeye d1: DOWN site:x", "HTTP 500", &["rotating_light"])
            .await
            .unwrap();
        wait_for(|| !sink.lock().unwrap().is_empty()).await;
        let got = sink.lock().unwrap().pop().unwrap();
        // Path: {url}/{topic}, nothing else.
        assert_eq!(got.path, "/test-topic");
        // JSON publish form: topic/title/message/priority/tags.
        assert_eq!(got.json["topic"], "test-topic");
        assert_eq!(got.json["title"], "echoeye d1: DOWN site:x");
        assert_eq!(got.json["message"], "HTTP 500");
        assert_eq!(got.json["priority"], 4);
        assert_eq!(got.json["tags"], serde_json::json!(["rotating_light"]));
    }

    #[tokio::test]
    async fn send_http_500_is_err_without_panic() {
        let (port, _sink) = spawn_fake_ntfy(axum::http::StatusCode::INTERNAL_SERVER_ERROR).await;
        let cfg = fake_cfg(port);
        let client = client();
        let res = send(&client, &cfg.url, &cfg.topic, 3, "t", "b", &[]).await;
        assert!(res.is_err(), "5xx from the ntfy server must surface as Err");
        assert!(res.unwrap_err().to_string().contains("500"));
    }

    #[tokio::test]
    async fn forwarder_formats_and_sends_each_event() {
        let (port, sink) = spawn_fake_ntfy(axum::http::StatusCode::OK).await;
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Event>();
        let handle = spawn_forwarder(rx, fake_cfg(port), "d1337".into());

        tx.send(ev(EventChange::Down, "site:importmath", Some("HTTP 500"))).unwrap();
        tx.send(ev(EventChange::Recovered, "site:importmath", None)).unwrap();
        wait_for(|| sink.lock().unwrap().len() == 2).await;

        // Extract under a short-lived guard, drop it BEFORE any await
        // (clippy: no MutexGuard across an await point).
        let (down, recovered) = {
            let mut all = sink.lock().unwrap();
            let recovered = all.pop().unwrap();
            (all.pop().unwrap(), recovered)
        };
        assert_eq!(down.json["title"], "echoeye d1337: DOWN site:importmath");
        assert_eq!(down.json["priority"], 4);
        assert_eq!(down.json["tags"], serde_json::json!(["rotating_light"]));
        assert_eq!(recovered.json["title"], "echoeye d1337: RECOVERED site:importmath");
        assert_eq!(recovered.json["priority"], 3);
        assert_eq!(recovered.json["tags"], serde_json::json!(["large_green_circle"]));

        // Dropping the tap ends the forwarder task cleanly.
        drop(tx);
        wait_for(|| handle.is_finished()).await;
    }
}
