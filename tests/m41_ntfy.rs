//! M4.1-c: integration tests for the ntfy push pipeline — the WHOLE
//! path "observation -> flap confirmation -> push" driven through the
//! production code: a single daemon-shaped node (real axum server,
//! real gossip loop, real check engine with the recorder attached),
//! wired by `cli::wire_ntfy` — the exact call `cli::run` performs —
//! with the real forwarder task, against a hand-rolled fake ntfy
//! server on loopback. No new dependencies, no real servers: only
//! 127.0.0.1 and the fictional topic `test-topic`.
//!
//! What is proven here, end to end — with every captured push parsed
//! as JSON (path + body fields, never text-grepped) and every
//! ABSENCE verified at an observable precondition (the probe history
//! ring), never after a blind sleep:
//!
//! * **full arc**: below-threshold failures push nothing; the
//!   threshold-th consecutive fail pushes EXACTLY ONE down
//!   (path `/test-topic`, title `echoeye <node>: DOWN site:…`,
//!   priority 4, siren tag, body carrying the HTTP status); the
//!   first success pushes exactly one recovered (priority 3, green
//!   tag) — two pushes and two events.jsonl lines for the whole arc;
//! * **anti-storm**: a persistent down (5+ further failed rounds)
//!   never pushes again — the flap tracker stays the only rate
//!   limiter all the way through the push pipeline;
//! * **dead channel**: a 500ing ntfy server still sees the POST
//!   attempt, the event lands in events.jsonl regardless, the node
//!   keeps observing (probes keep counting, /api/state keeps
//!   answering), the forwarder survives WITHOUT retrying the failed
//!   push — and delivers the NEXT event as soon as the channel is
//!   back (delivery is best-effort, never fatal, never blocking);
//! * **legacy**: without `[ntfy]` (and without a network channel)
//!   nothing is ever sent, while the event history keeps working
//!   (M4.4: the forwarder is always wired now — silence comes from
//!   the per-event channel resolution, not a missing subscription);
//! * **fan-out**: two checks confirm and push independently — four
//!   pushes for two arcs, every title carrying node name AND target.

use echoeye::checks::{CheckOutcome, CheckRecord, Engine, HttpCheckSpec, SiteProbe};
use echoeye::config::{NetworkConfig, NodeEntry};
use echoeye::events::{Event, EventChange};
use echoeye::ntfy::NtfySection;
use echoeye::transport::{self, NodeClient, NodeState};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;

const PHASE_DEADLINE: Duration = Duration::from_secs(35);
const POLL_STEP: Duration = Duration::from_millis(250);
/// The node name every push title must carry (set in the config).
const NODE_NAME: &str = "push-node";

static DIR_SEQ: AtomicUsize = AtomicUsize::new(0);

/// Fresh tempdir per test (parallel tests would collide otherwise);
/// the `logs` subdir mirrors the daemon layout (`<dir>/logs/events.jsonl`).
fn tmp(tag: &str) -> PathBuf {
    let n = DIR_SEQ.fetch_add(1, Ordering::SeqCst);
    let d = std::env::temp_dir().join(format!("em-m41c-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("logs")).expect("tempdir");
    d
}

/// Read events.jsonl STRICTLY: every non-empty line must parse as an
/// [`Event`] or the test panics — same contract as the m37 harness.
/// A missing file is an empty history.
fn read_events(path: &Path) -> Vec<Event> {
    let raw = match std::fs::read_to_string(path) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<Event>(line) {
            Ok(ev) => out.push(ev),
            Err(e) => panic!(
                "events.jsonl:{} is not a valid event line ({e}): {line:?}",
                i + 1
            ),
        }
    }
    out
}

async fn poll_until<F, Fut, D, DFut>(what: &str, mut check: F, mut diag: D)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
    D: FnMut() -> DFut,
    DFut: Future<Output = String>,
{
    let t0 = Instant::now();
    loop {
        if check().await {
            return;
        }
        assert!(
            t0.elapsed() < PHASE_DEADLINE,
            "timed out waiting for: {what} (elapsed {:?})\n{}",
            t0.elapsed(),
            diag().await
        );
        tokio::time::sleep(POLL_STEP).await;
    }
}

fn has_change(evs: &[Event], target: &str, change: EventChange) -> bool {
    evs.iter().any(|e| e.target == target && e.change == change)
}

// ---------- node harness (m37 style, single node) ----------

struct Node {
    addr: String,
    rt: Option<Runtime>,
}

impl Node {
    /// Kill the node's whole runtime: server, gossip, forwarder and
    /// check engine all drop at once — the m27 lesson.
    fn kill(&mut self) {
        if let Some(rt) = self.rt.take() {
            rt.shutdown_timeout(Duration::from_millis(0));
        }
    }
}

/// Single-node config: fast gossip, monitors off except the caller's
/// HTTP checks, threshold from the caller, optional `[ntfy]`. The
/// self node's address points at a dead port (nothing there), so the
/// only possible events and pushes come from the checks themselves.
fn single_node_cfg(
    secret: &str,
    threshold: u32,
    checks: Vec<HttpCheckSpec>,
    ntfy: Option<NtfySection>,
) -> NetworkConfig {
    let mut cfg = NetworkConfig::bootstrap(secret.to_string(), NODE_NAME.to_string());
    cfg.self_id = 1;
    cfg.net.gossip_interval_secs = 1;
    cfg.net.ssh_check_interval_secs = 0;
    cfg.net.docker_check_interval_secs = 0;
    cfg.net.flap_fail_threshold = threshold;
    cfg.nodes = vec![NodeEntry {
        id: 1,
        name: NODE_NAME.to_string(),
        public_key: None,
        address: Some("127.0.0.1:1".into()),
        ssh: None,
    }];
    cfg.edges = Vec::new();
    cfg.checks = checks;
    cfg.ntfy = ntfy;
    cfg.recompute_hash();
    cfg
}

/// Daemon-shaped single node: events log armed first, then the ntfy
/// tap wired via `cli::wire_ntfy` (the exact `cli::run` call) BEFORE
/// the check engine starts — the same ordering guarantee as the real
/// daemon, so no confirmed transition can slip past the tap. The
/// forwarder task lives on the node's own runtime: killing the node
/// kills its pusher too.
async fn spawn_node(cfg: NetworkConfig, events_path: PathBuf) -> (Node, Arc<NodeState>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("node runtime");
    let state = Arc::new(NodeState::new(cfg.clone()));
    state.enable_events_log(events_path);
    let srv_state = state.clone();
    rt.spawn(async move {
        axum::serve(listener, transport::router(srv_state))
            .await
            .expect("node server");
    });
    // The cli::run wiring, verbatim placement: after the event log is
    // armed and before any monitor loop that can produce events.
    let wire_state = state.clone();
    rt.spawn(async move {
        // M4.4: the forwarder is ALWAYS spawned (per-event channel
        // resolution: local [ntfy] > network channel > silent).
        let _ = echoeye::cli::wire_ntfy(&wire_state, &cfg);
    });
    let loop_state = state.clone();
    rt.spawn(async move {
        transport::spawn_gossip_loop(loop_state);
    });
    (Node { addr, rt: Some(rt) }, state)
}

/// The `cli::run` check-engine wiring, verbatim from the m37 harness:
/// engine with the node's recorder attached, finished records tapped
/// into the shared probe table, the task spawned ON THE NODE'S OWN
/// RUNTIME so killing the node kills its probes too.
fn spawn_check_engine(
    node: &Node,
    state: &Arc<NodeState>,
    threshold: u32,
    specs: Vec<HttpCheckSpec>,
) -> Arc<Engine> {
    let self_id = state.cfg.read().unwrap().self_id;
    let sink_state = state.clone();
    let engine = Arc::new(
        Engine::new(10, threshold)
            .with_events(state.events.clone())
            .with_sink(Arc::new(move |rec: &CheckRecord| {
                sink_state.record_own_probe(SiteProbe {
                    check_id: rec.check.clone(),
                    node_id: self_id,
                    measured_at: rec.at,
                    outcome: rec.outcome.clone(),
                    status: rec.status,
                    ip: rec.ip.clone(),
                });
            })),
    );
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let e = engine.clone();
    node.rt
        .as_ref()
        .expect("node runtime alive")
        .spawn(async move {
            e.run(specs, shutdown_rx).await;
        });
    // Same as the daemon: keep the sender alive for the node's lifetime.
    std::mem::forget(shutdown_tx);
    engine
}

/// Consecutive failures at the tail of a check's history ring — how
/// the test counts probe rounds without touching clocks.
async fn consec_fails(engine: &Engine, name: &str) -> u32 {
    let hs = engine.histories.lock().await;
    match hs.get(name) {
        Some(h) => h.lock().await.consecutive_fails(),
        None => 0,
    }
}

/// True when the newest record of a check is an Ok.
async fn last_probe_ok(engine: &Engine, name: &str) -> bool {
    let hs = engine.histories.lock().await;
    match hs.get(name) {
        Some(h) => matches!(
            h.lock().await.recent().back(),
            Some(rec) if matches!(rec.outcome, CheckOutcome::Ok { .. })
        ),
        None => false,
    }
}

// ---------- hand-rolled loopback servers (no new deps) ----------

/// Flippable HTTP target: 200 "ok" while the flag is set, 500 once it
/// is cleared (same shape as the m37 harness — reqwest reads it fine).
async fn flippable_http(l: TcpListener, flag: Arc<AtomicBool>) {
    while let Ok((mut sock, _)) = l.accept().await {
        let mut req = [0u8; 1024];
        let _ = sock.read(&mut req).await;
        let resp = if flag.load(Ordering::Relaxed) {
            "HTTP/1.0 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
        } else {
            "HTTP/1.0 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        };
        let _ = sock.write_all(resp.as_bytes()).await;
    }
}

/// What the fake ntfy captured: request path + decoded JSON body.
#[derive(Debug, Clone)]
struct Captured {
    path: String,
    json: serde_json::Value,
}

/// Copy the capture list under a short-lived guard (never held across
/// an await point).
fn snapshot(sink: &Arc<Mutex<Vec<Captured>>>) -> Vec<Captured> {
    sink.lock().unwrap().clone()
}

/// Fake ntfy on loopback: captures every POST (path + parsed JSON
/// body) and answers 200 while `healthy` is set, 500 once it is
/// cleared — the "dead channel" dial. The capture happens BEFORE the
/// status decision, so failed-delivery attempts are visible too.
async fn spawn_fake_ntfy(healthy: Arc<AtomicBool>) -> (u16, Arc<Mutex<Vec<Captured>>>) {
    let sink: Arc<Mutex<Vec<Captured>>> = Arc::new(Mutex::new(Vec::new()));
    let sink_route = sink.clone();
    let routes = axum::Router::new().route(
        "/test-topic",
        axum::routing::post(move |uri: axum::http::Uri, body: String| {
            let sink = sink_route.clone();
            let healthy = healthy.clone();
            async move {
                sink.lock().unwrap().push(Captured {
                    path: uri.path().to_string(),
                    json: serde_json::from_str(&body).unwrap_or(serde_json::Value::Null),
                });
                if healthy.load(Ordering::Relaxed) {
                    axum::http::StatusCode::OK
                } else {
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR
                }
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, routes).await.unwrap() });
    (port, sink)
}

fn ntfy_cfg(port: u16) -> NtfySection {
    NtfySection {
        url: format!("http://127.0.0.1:{port}"),
        topic: "test-topic".into(),
        priority_down: 4,
        priority_recovered: 3,
    }
}

async fn push_diag(sink: &Arc<Mutex<Vec<Captured>>>, events_path: &Path) -> String {
    format!(
        "pushes so far: {:?}\nevents so far: {:?}",
        snapshot(sink),
        read_events(events_path)
    )
}

// =====================================================================
// 1. Full arc: silence below the threshold, ONE down push on the Nth
//    fail (full field check), ONE recovered push on the first success.
// =====================================================================
#[tokio::test]
async fn full_arc_down_push_then_recovered_push() {
    const THRESHOLD: u32 = 2;
    const CHECK: &str = "push-site";
    let target_str = format!("site:{CHECK}");

    let flag = Arc::new(AtomicBool::new(true));
    let tl = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_port = tl.local_addr().unwrap().port();
    tokio::spawn(flippable_http(tl, flag.clone()));

    let (ntfy_port, sink) = spawn_fake_ntfy(Arc::new(AtomicBool::new(true))).await;

    let dir = tmp("arc");
    let events_path = dir.join("logs").join("events.jsonl");
    let cfg = single_node_cfg(
        "m41c-arc",
        THRESHOLD,
        vec![HttpCheckSpec {
            name: CHECK.into(),
            url: format!("http://127.0.0.1:{target_port}/health"),
            expect: Some(200),
            interval: Some(1),
            timeout: Some(1),
        }],
        Some(ntfy_cfg(ntfy_port)),
    );
    let (mut node, state) = spawn_node(cfg, events_path.clone()).await;
    let engine = spawn_check_engine(
        &node,
        &state,
        THRESHOLD,
        state.cfg.read().unwrap().checks.clone(),
    );

    // --- healthy baseline: the first Ok probe must not push anything.
    poll_until(
        "baseline Ok probe recorded",
        || async { last_probe_ok(&engine, CHECK).await },
        || push_diag(&sink, &events_path),
    )
    .await;
    assert!(
        snapshot(&sink).is_empty(),
        "healthy baseline must not push: {:?}",
        snapshot(&sink)
    );

    // --- below the threshold: the ABSENCE of a push is verified at an
    // observable precondition (a failed probe has landed), race-free
    // by construction — with threshold 2 one landed fail cannot have
    // fired anything.
    flag.store(false, Ordering::Relaxed);
    poll_until(
        "first failed probe recorded",
        || async { consec_fails(&engine, CHECK).await >= 1 },
        || push_diag(&sink, &events_path),
    )
    .await;
    assert!(
        snapshot(&sink).is_empty(),
        "no push below {THRESHOLD} consecutive fails: {:?}",
        snapshot(&sink)
    );
    assert!(
        !has_change(&read_events(&events_path), &target_str, EventChange::Down),
        "no down event below the threshold either"
    );

    // --- the Nth consecutive fail: EXACTLY ONE down push, every field.
    poll_until(
        "down push captured by the fake ntfy",
        || async { snapshot(&sink).len() == 1 },
        || push_diag(&sink, &events_path),
    )
    .await;
    {
        let evs = read_events(&events_path);
        assert_eq!(evs.len(), 1, "one event so far: {evs:?}");
        assert_eq!(
            (evs[0].target.as_str(), evs[0].change),
            (target_str.as_str(), EventChange::Down)
        );
        let pushes = snapshot(&sink);
        assert_eq!(pushes.len(), 1, "exactly ONE push, not one per round");
        let down = &pushes[0];
        assert_eq!(down.path, "/test-topic", "publish endpoint = url/topic");
        assert_eq!(down.json["topic"], "test-topic");
        assert_eq!(
            down.json["title"],
            format!("echoeye {NODE_NAME}: DOWN {target_str}"),
            "title carries node name, direction and target"
        );
        assert_eq!(down.json["priority"], 4, "down pushes at priority 4");
        assert_eq!(down.json["tags"], serde_json::json!(["rotating_light"]));
        assert!(
            down.json["message"].as_str().unwrap_or_default().contains("500"),
            "down body carries the HTTP status, got: {}",
            down.json["message"]
        );
    }

    // --- first success: EXACTLY ONE recovered push, two pushes total
    // for the whole arc.
    flag.store(true, Ordering::Relaxed);
    poll_until(
        "recovered push captured by the fake ntfy",
        || async {
            let s = snapshot(&sink);
            s.len() == 2
                && s[1]
                    .json["title"]
                    .as_str()
                    .is_some_and(|t| t.contains("RECOVERED"))
        },
        || push_diag(&sink, &events_path),
    )
    .await;
    {
        let evs = read_events(&events_path);
        assert_eq!(evs.len(), 2, "the whole arc is exactly two events: {evs:?}");
        assert_eq!(evs[1].change, EventChange::Recovered);
        let pushes = snapshot(&sink);
        assert_eq!(pushes.len(), 2, "the whole arc is exactly two pushes");
        let rec = &pushes[1];
        assert_eq!(rec.path, "/test-topic");
        assert_eq!(
            rec.json["title"],
            format!("echoeye {NODE_NAME}: RECOVERED {target_str}")
        );
        assert_eq!(rec.json["priority"], 3, "recovered pushes at priority 3");
        assert_eq!(rec.json["tags"], serde_json::json!(["large_green_circle"]));
        assert!(
            evs[1].at_ms >= evs[0].at_ms,
            "recovered cannot predate down: {evs:?}"
        );
    }

    node.kill();
}

// =====================================================================
// 2. Anti-storm through the whole pipeline: a persistent down (five
//    and more failed rounds) pushes ONCE — the flap tracker upstream
//    stays the only rate limiter, the pusher adds no storm of its own.
// =====================================================================
#[tokio::test]
async fn persistent_down_pushes_once_no_storm() {
    const THRESHOLD: u32 = 2;
    const CHECK: &str = "storm-site";
    let target_str = format!("site:{CHECK}");

    let flag = Arc::new(AtomicBool::new(true));
    let tl = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_port = tl.local_addr().unwrap().port();
    tokio::spawn(flippable_http(tl, flag.clone()));

    let (ntfy_port, sink) = spawn_fake_ntfy(Arc::new(AtomicBool::new(true))).await;

    let dir = tmp("storm");
    let events_path = dir.join("logs").join("events.jsonl");
    let cfg = single_node_cfg(
        "m41c-storm",
        THRESHOLD,
        vec![HttpCheckSpec {
            name: CHECK.into(),
            url: format!("http://127.0.0.1:{target_port}/health"),
            expect: Some(200),
            interval: Some(1),
            timeout: Some(1),
        }],
        Some(ntfy_cfg(ntfy_port)),
    );
    let (mut node, state) = spawn_node(cfg, events_path.clone()).await;
    let engine = spawn_check_engine(
        &node,
        &state,
        THRESHOLD,
        state.cfg.read().unwrap().checks.clone(),
    );

    poll_until(
        "baseline Ok probe recorded",
        || async { last_probe_ok(&engine, CHECK).await },
        || push_diag(&sink, &events_path),
    )
    .await;
    flag.store(false, Ordering::Relaxed);
    poll_until(
        "the single down push captured",
        || async { snapshot(&sink).len() == 1 },
        || push_diag(&sink, &events_path),
    )
    .await;

    // Five-plus further failed rounds while down (observable in the
    // probe ring) — still exactly one push and one event, no storm.
    poll_until(
        "five failed rounds accumulated while down",
        || async { consec_fails(&engine, CHECK).await >= 5 },
        || push_diag(&sink, &events_path),
    )
    .await;
    assert_eq!(
        snapshot(&sink).len(),
        1,
        "persistent down must not re-push: {:?}",
        snapshot(&sink)
    );
    assert_eq!(
        read_events(&events_path).len(),
        1,
        "persistent down must not re-record: {:?}",
        read_events(&events_path)
    );
    assert!(has_change(
        &read_events(&events_path),
        &target_str,
        EventChange::Down
    ));

    node.kill();
}

// =====================================================================
// 3. Dead channel: the fake ntfy 500s from birth. The down event
//    still lands in events.jsonl (delivery never kills observation),
//    the POST is attempted ONCE and never retried, the node keeps
//    observing (probes keep counting, /api/state keeps answering) —
//    and once the channel is back the NEXT event is delivered.
// =====================================================================
#[tokio::test]
async fn dead_channel_keeps_observation_and_delivers_next_event() {
    const THRESHOLD: u32 = 2;
    const CHECK: &str = "chan-site";
    let target_str = format!("site:{CHECK}");

    let flag = Arc::new(AtomicBool::new(true));
    let tl = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_port = tl.local_addr().unwrap().port();
    tokio::spawn(flippable_http(tl, flag.clone()));

    // healthy=false: every POST is captured but answered with 500.
    let channel_healthy = Arc::new(AtomicBool::new(false));
    let (ntfy_port, sink) = spawn_fake_ntfy(channel_healthy.clone()).await;

    let dir = tmp("deadchan");
    let events_path = dir.join("logs").join("events.jsonl");
    let cfg = single_node_cfg(
        "m41c-deadchan",
        THRESHOLD,
        vec![HttpCheckSpec {
            name: CHECK.into(),
            url: format!("http://127.0.0.1:{target_port}/health"),
            expect: Some(200),
            interval: Some(1),
            timeout: Some(1),
        }],
        Some(ntfy_cfg(ntfy_port)),
    );
    let (mut node, state) = spawn_node(cfg, events_path.clone()).await;
    let engine = spawn_check_engine(
        &node,
        &state,
        THRESHOLD,
        state.cfg.read().unwrap().checks.clone(),
    );
    let obs = NodeClient::new("m41c-deadchan".into(), 99);

    poll_until(
        "baseline Ok probe recorded",
        || async { last_probe_ok(&engine, CHECK).await },
        || push_diag(&sink, &events_path),
    )
    .await;

    // Down while the channel is dead: the push is ATTEMPTED (captured)
    // and rejected with 500 — but the event itself is safely recorded.
    flag.store(false, Ordering::Relaxed);
    poll_until(
        "down push attempt captured despite the 500s",
        || async { snapshot(&sink).len() == 1 },
        || push_diag(&sink, &events_path),
    )
    .await;
    {
        let evs = read_events(&events_path);
        assert_eq!(evs.len(), 1, "delivery failure must not lose the event: {evs:?}");
        assert_eq!(
            (evs[0].target.as_str(), evs[0].change),
            (target_str.as_str(), EventChange::Down)
        );
        let attempt = &snapshot(&sink)[0];
        assert!(
            attempt.json["title"]
                .as_str()
                .is_some_and(|t| t.contains("DOWN")),
            "the attempted (failed) push was the down one: {:?}",
            attempt.json
        );
    }

    // Observation stays alive through the dead-channel window: probes
    // keep counting (two-plus further rounds) and the node's API still
    // answers; the failed push is NOT retried (still one POST total).
    poll_until(
        "engine keeps probing while the channel is dead",
        || async { consec_fails(&engine, CHECK).await >= 4 },
        || push_diag(&sink, &events_path),
    )
    .await;
    assert_eq!(
        snapshot(&sink).len(),
        1,
        "a failed push must not be retried: {:?}",
        snapshot(&sink)
    );
    assert!(
        obs.state(&node.addr).await.is_ok(),
        "the node's API must keep answering while its push channel is dead"
    );

    // Channel recovers, then the target recovers: the NEXT event is
    // delivered — the forwarder survived, unstuck, and never resent
    // the old down.
    channel_healthy.store(true, Ordering::Relaxed);
    flag.store(true, Ordering::Relaxed);
    poll_until(
        "recovered push delivered after the channel came back",
        || async {
            let s = snapshot(&sink);
            s.len() == 2
                && s[1]
                    .json["title"]
                    .as_str()
                    .is_some_and(|t| t.contains("RECOVERED"))
        },
        || push_diag(&sink, &events_path),
    )
    .await;
    let pushes = snapshot(&sink);
    assert_eq!(
        pushes[0].json["title"],
        format!("echoeye {NODE_NAME}: DOWN {target_str}"),
        "the first POST stays the old down attempt — no resend, no reorder"
    );
    assert_eq!(
        pushes[1].json["title"],
        format!("echoeye {NODE_NAME}: RECOVERED {target_str}")
    );
    assert_eq!(
        read_events(&events_path).len(),
        2,
        "the whole arc is exactly two events: {:?}",
        read_events(&events_path)
    );

    node.kill();
}

// =====================================================================
// 4. Legacy: without `[ntfy]` the wiring subscribes nothing and the
//    node never sends a single POST anywhere — while the confirmed
//    transitions still land in events.jsonl exactly as before M4.1.
// =====================================================================
#[tokio::test]
async fn no_ntfy_section_is_legacy_silent() {
    const THRESHOLD: u32 = 2;
    const CHECK: &str = "legacy-site";
    let target_str = format!("site:{CHECK}");

    let flag = Arc::new(AtomicBool::new(true));
    let tl = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_port = tl.local_addr().unwrap().port();
    tokio::spawn(flippable_http(tl, flag.clone()));

    // A live, healthy fake ntfy exists on loopback — if anything were
    // ever sent, it would land here. Nothing knows its address.
    let (_ntfy_port, sink) = spawn_fake_ntfy(Arc::new(AtomicBool::new(true))).await;

    let dir = tmp("legacy");
    let events_path = dir.join("logs").join("events.jsonl");
    let cfg = single_node_cfg(
        "m41c-legacy",
        THRESHOLD,
        vec![HttpCheckSpec {
            name: CHECK.into(),
            url: format!("http://127.0.0.1:{target_port}/health"),
            expect: Some(200),
            interval: Some(1),
            timeout: Some(1),
        }],
        None,
    );
    assert!(cfg.ntfy.is_none());
    let (mut node, state) = spawn_node(cfg.clone(), events_path.clone()).await;
    // M4.4 semantics: the wiring now ALWAYS subscribes and spawns
    // (the channel resolves per event); the legacy guarantee that
    // survives is the one below — without a local section AND without
    // a network channel, nothing is ever sent anywhere.
    assert!(
        echoeye::cli::wire_ntfy(&state, &cfg).is_some(),
        "M4.4: the forwarder is always wired, silence comes from resolution"
    );
    let engine = spawn_check_engine(
        &node,
        &state,
        THRESHOLD,
        state.cfg.read().unwrap().checks.clone(),
    );

    // The full down+recovered arc — recorded, but never pushed.
    poll_until(
        "baseline Ok probe recorded",
        || async { last_probe_ok(&engine, CHECK).await },
        || push_diag(&sink, &events_path),
    )
    .await;
    flag.store(false, Ordering::Relaxed);
    poll_until(
        "down confirmed without any push channel",
        || async {
            has_change(&read_events(&events_path), &target_str, EventChange::Down)
        },
        || push_diag(&sink, &events_path),
    )
    .await;
    flag.store(true, Ordering::Relaxed);
    poll_until(
        "recovered confirmed without any push channel",
        || async {
            has_change(&read_events(&events_path), &target_str, EventChange::Recovered)
        },
        || push_diag(&sink, &events_path),
    )
    .await;

    let evs = read_events(&events_path);
    assert_eq!(evs.len(), 2, "the event history works as before: {evs:?}");
    assert!(
        snapshot(&sink).is_empty(),
        "legacy config must never send anything: {:?}",
        snapshot(&sink)
    );

    node.kill();
}

// =====================================================================
// 5. Fan-out: two checks on the same flippable target confirm and
//    push independently — four pushes for two arcs, every title
//    carrying the node name AND its own target, priorities following
//    the direction.
// =====================================================================
#[tokio::test]
async fn two_checks_fan_out_four_pushes_with_node_and_target() {
    const THRESHOLD: u32 = 2;

    let flag = Arc::new(AtomicBool::new(true));
    let tl = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_port = tl.local_addr().unwrap().port();
    tokio::spawn(flippable_http(tl, flag.clone()));

    let (ntfy_port, sink) = spawn_fake_ntfy(Arc::new(AtomicBool::new(true))).await;

    let spec = |name: &str| HttpCheckSpec {
        name: name.into(),
        url: format!("http://127.0.0.1:{target_port}/health"),
        expect: Some(200),
        interval: Some(1),
        timeout: Some(1),
    };

    let dir = tmp("fanout");
    let events_path = dir.join("logs").join("events.jsonl");
    let cfg = single_node_cfg(
        "m41c-fanout",
        THRESHOLD,
        vec![spec("multi-a"), spec("multi-b")],
        Some(ntfy_cfg(ntfy_port)),
    );
    let (mut node, state) = spawn_node(cfg, events_path.clone()).await;
    let engine = spawn_check_engine(
        &node,
        &state,
        THRESHOLD,
        state.cfg.read().unwrap().checks.clone(),
    );

    // Baseline: BOTH checks Ok, nothing pushed.
    poll_until(
        "both checks have a baseline Ok probe",
        || async { last_probe_ok(&engine, "multi-a").await && last_probe_ok(&engine, "multi-b").await },
        || push_diag(&sink, &events_path),
    )
    .await;
    assert!(snapshot(&sink).is_empty());

    // Both go down: two down pushes (order between checks is not
    // fixed — compare as a set).
    flag.store(false, Ordering::Relaxed);
    poll_until(
        "both down pushes captured",
        || async { snapshot(&sink).len() == 2 },
        || push_diag(&sink, &events_path),
    )
    .await;

    // Both recover: four pushes total, two per direction.
    flag.store(true, Ordering::Relaxed);
    poll_until(
        "both recovered pushes captured",
        || async { snapshot(&sink).len() == 4 },
        || push_diag(&sink, &events_path),
    )
    .await;

    let mut titles: Vec<String> = snapshot(&sink)
        .iter()
        .map(|c| c.json["title"].as_str().unwrap_or_default().to_string())
        .collect();
    titles.sort();
    let mut expected = vec![
        format!("echoeye {NODE_NAME}: DOWN site:multi-a"),
        format!("echoeye {NODE_NAME}: DOWN site:multi-b"),
        format!("echoeye {NODE_NAME}: RECOVERED site:multi-a"),
        format!("echoeye {NODE_NAME}: RECOVERED site:multi-b"),
    ];
    expected.sort();
    assert_eq!(titles, expected, "four pushes, node + target in every title");

    // Priority follows the direction in every single push.
    for c in snapshot(&sink) {
        let is_down = c.json["title"]
            .as_str()
            .is_some_and(|t| t.contains("DOWN"));
        let want = if is_down { 4 } else { 3 };
        assert_eq!(c.json["priority"], want, "direction/priority mismatch: {:?}", c.json);
    }

    // And the durable history agrees: four events, all four targets.
    let evs = read_events(&events_path);
    assert_eq!(evs.len(), 4, "two arcs = four events: {evs:?}");
    let mut targets: Vec<&str> = evs.iter().map(|e| e.target.as_str()).collect();
    targets.sort();
    assert_eq!(
        targets,
        vec!["site:multi-a", "site:multi-a", "site:multi-b", "site:multi-b"]
    );

    node.kill();
}
