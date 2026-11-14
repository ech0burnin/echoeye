//! M3.7: integration tests for the flap-guarded event history — the
//! minimal meshes in which events are really BORN, driven through the
//! production code paths (real gossip loop, real check engine, real
//! ssh-matrix loop, each in its own single-worker runtime like m27/m32/m35;
//! kill = runtime shutdown_timeout(0)).
//!
//! What is proven here, end to end, with events.jsonl parsed line by
//! line as JSON (never text-grepped):
//!
//! * **site flap**: a check target failing below the threshold stays
//!   silent (the absence is verified at an observable precondition —
//!   the probe history shows the failure count — not after a blind
//!   sleep), the N-th consecutive fail confirms ONE `down` (not N),
//!   further fails stay silent (no storm), the first success emits
//!   `recovered`;
//! * **liveness**: a peer's death is observed from evidence staleness,
//!   not instantly — the event timestamp is provably >= last successful
//!   contact + t_dead — and exactly once; a returning peer recovers;
//! * **ssh pair**: killing a fake sshd (TCP refused = fast fail) yields
//!   `ssh:1->2 down` after the threshold, rebinding yields `recovered`;
//! * **file discipline**: without `enable_events_log` the recorder stays
//!   pure memory and events.jsonl is NEVER created, even after confirmed
//!   transitions; attaching the sink mid-life writes only FUTURE
//!   transitions (no retroactive backfill);
//! * **anti-storm**: a healthy mesh and never-contacted peers produce
//!   no events at all.
//!
//! The real /var/run/docker.sock and real systemd units are never
//! touched (docker interval 0 everywhere, no units configured); the
//! HTTP target and the fake sshd are hand-rolled loopback servers.

use echoeye::checks::{CheckOutcome, CheckRecord, Engine, HttpCheckSpec, SiteProbe};
use echoeye::config::{EdgeEntry, NetworkConfig, NodeEntry, SshDial};
use echoeye::events::{Event, EventChange};
use echoeye::sshmatrix::SshProbe;
use echoeye::transport::{self, NodeClient, NodeState};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;

const PHASE_DEADLINE: Duration = Duration::from_secs(35);
const POLL_STEP: Duration = Duration::from_millis(250);

static DIR_SEQ: AtomicUsize = AtomicUsize::new(0);

/// Fresh tempdir per node/test (parallel tests would collide otherwise);
/// same convention as the m35 harness. The `logs` subdir mirrors the
/// daemon's directory layout (`<dir>/logs/events.jsonl`).
fn tmp(tag: &str) -> PathBuf {
    let n = DIR_SEQ.fetch_add(1, Ordering::SeqCst);
    let d = std::env::temp_dir().join(format!("em-m37c-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("logs")).expect("tempdir");
    d
}

/// Read events.jsonl STRICTLY: every non-empty line must parse as an
/// [`Event`] or the test panics — the whole point of this suite is that
/// the file is a machine contract, so a malformed line is a failure,
/// not noise to filter away. A missing file is an empty history.
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

// ---------- mesh harness (m32/m35 style) ----------

struct Node {
    addr: String,
    rt: Option<Runtime>,
}

impl Node {
    /// The live runtime (for spawning node-owned tasks after birth).
    fn runtime(&self) -> &Runtime {
        self.rt.as_ref().expect("node runtime alive")
    }

    /// Kill the node's whole runtime: every socket it owns (axum server,
    /// in-flight probes) drops at once — the m27 lesson.
    fn kill(&mut self) {
        if let Some(rt) = self.rt.take() {
            rt.shutdown_timeout(Duration::from_millis(0));
        }
    }
}

/// Two-node mesh config: fast gossip, monitors off unless a test turns
/// them on, threshold from the caller. The whole `net` section is local
/// tuning (never part of the admin hash), so per-test values are fine.
fn mesh_config(
    secret: &str,
    self_id: u32,
    gossip_ports: &[u16; 2],
    interval: u64,
    threshold: u32,
) -> NetworkConfig {
    let mut cfg = NetworkConfig::bootstrap(secret.to_string(), format!("node-{self_id}"));
    cfg.self_id = self_id;
    cfg.net.gossip_interval_secs = interval;
    cfg.net.ssh_check_interval_secs = 0;
    cfg.net.docker_check_interval_secs = 0;
    cfg.net.flap_fail_threshold = threshold;
    cfg.nodes = (1..=2u32)
        .map(|i| NodeEntry {
            id: i,
            name: format!("node-{i}"),
            public_key: None,
            address: Some(format!("127.0.0.1:{}", gossip_ports[(i - 1) as usize])),
            ssh: None,
        })
        .collect();
    cfg.edges = vec![EdgeEntry { a: 1, b: 2, latency_ms: None }];
    cfg.recompute_hash();
    cfg
}

/// One node = one dedicated single-worker runtime carrying the REAL axum
/// server and the REAL gossip loop (the exact production path `cli::run`
/// spawns). The events JSONL sink is attached BEFORE any loop starts,
/// mirroring the daemon's ordering; `None` keeps the recorder pure
/// memory (the file-discipline test relies on that).
fn spawn_node(
    cfg: NetworkConfig,
    listener: TcpListener,
    events_path: Option<PathBuf>,
    with_ssh_matrix: bool,
) -> (Node, Arc<NodeState>) {
    let addr = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("node runtime");
    let state = Arc::new(NodeState::new(cfg));
    if let Some(p) = events_path {
        state.enable_events_log(p);
    }
    let srv_state = state.clone();
    rt.spawn(async move {
        axum::serve(listener, transport::router(srv_state))
            .await
            .expect("node server");
    });
    let loop_state = state.clone();
    rt.spawn(async move {
        transport::spawn_gossip_loop(loop_state);
    });
    if with_ssh_matrix {
        let ssh_state = state.clone();
        rt.spawn(async move {
            echoeye::sshmatrix::spawn_ssh_matrix_loop(ssh_state);
        });
    }
    (Node { addr, rt: Some(rt) }, state)
}

/// The `cli::run` check-engine wiring, verbatim: engine with the node's
/// recorder attached, every finished record tapped into the shared
/// probe table, the task spawned ON THE NODE'S OWN RUNTIME so killing
/// the node kills its probes too. The returned Arc lets the test watch
/// the probe history — the observable precondition for absence checks.
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
    node.runtime().spawn(async move {
        e.run(specs, shutdown_rx).await;
    });
    // Same as the daemon: keep the sender alive for the node's lifetime
    // (dropping it would flip the watch and shut the engine down).
    std::mem::forget(shutdown_tx);
    engine
}

/// Consecutive failures at the tail of a check's history ring — how the
/// test counts probe rounds without touching clocks.
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
/// is cleared. HTTP/1.0 + close framing, the same shape the docker
/// harness uses — reqwest (the real probe client) reads it fine.
/// Takes the ALREADY-BOUND listener (the caller reserved the port).
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

/// A fake system sshd: greets every client with a banner line and keeps
/// the socket open (exactly what `ssh_probe` needs to see).
async fn fake_sshd(l: TcpListener) {
    while let Ok((mut sock, _)) = l.accept().await {
        let _ = sock.write_all(b"SSH-2.0-ECHOEYE_M37C_FAKE\r\n").await;
    }
}

// ---------- shared small helpers ----------

/// Latest evidence timestamp node `addr` holds about `id` (from /api/state).
async fn seen_at(obs: &NodeClient, addr: &str, id: u32) -> Option<u64> {
    obs.state(addr)
        .await
        .ok()?
        .seen
        .iter()
        .find(|s| s.id == id)
        .map(|s| s.at_ms)
}

/// The ssh row (from -> to) as node `addr` currently sees it.
async fn ssh_row(obs: &NodeClient, addr: &str, from: u32, to: u32) -> Option<SshProbe> {
    obs.state(addr)
        .await
        .ok()?
        .ssh
        .iter()
        .find(|p| p.from == from && p.to == to)
        .cloned()
}

fn has_change(evs: &[Event], target: &str, change: EventChange) -> bool {
    evs.iter().any(|e| e.target == target && e.change == change)
}

async fn events_diag(path: &Path) -> String {
    format!("events so far: {:?}", read_events(path))
}

// =====================================================================
// 1. Site flap: silence below the threshold, ONE down on the Nth fail,
//    no storm while down, one recovered on the first success.
// =====================================================================
#[tokio::test]
async fn site_flap_down_on_nth_fail_single_event_then_recovered() {
    const THRESHOLD: u32 = 3; // the config default — proves the plumbing
    const CHECK: &str = "flap-site";
    let target_str = format!("site:{CHECK}");

    // The flippable target lives in the test's runtime; the node dials
    // it over plain loopback TCP, so runtime boundaries do not matter.
    let flag = Arc::new(AtomicBool::new(true));
    let tl = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_port = tl.local_addr().unwrap().port();
    tokio::spawn(flippable_http(tl, flag.clone()));

    let dir = tmp("flap");
    let events_path = dir.join("logs").join("events.jsonl");

    let mut cfg = mesh_config("m37c-flap", 1, &[1, 1], 1, THRESHOLD);
    // Single-node mesh: the second node entry is dropped so no liveness
    // observations exist at all — the ONLY possible events here are the
    // site's own.
    cfg.nodes.truncate(1);
    cfg.edges.clear();
    cfg.checks = vec![HttpCheckSpec {
        name: CHECK.into(),
        url: format!("http://127.0.0.1:{target_port}/health"),
        expect: Some(200),
        interval: Some(1),
        timeout: Some(1),
    }];
    cfg.recompute_hash();

    let (mut node, state) = spawn_node(
        cfg,
        TcpListener::bind("127.0.0.1:0").await.unwrap(),
        Some(events_path.clone()),
        false,
    );
    let engine = spawn_check_engine(
        &node,
        &state,
        THRESHOLD,
        state.cfg.read().unwrap().checks.clone(),
    );

    // --- phase 1: healthy baseline — the first observation seeds the
    // state and must not produce any event (anti-storm at boot).
    poll_until(
        "baseline Ok probe recorded",
        || async { last_probe_ok(&engine, CHECK).await },
        || events_diag(&events_path),
    )
    .await;
    assert!(
        read_events(&events_path).is_empty(),
        "healthy baseline must not produce events: {:?}",
        read_events(&events_path)
    );

    // --- phase 2: target starts failing. Verify the ABSENCE of a down
    // event at an observable precondition: the history ring has counted
    // failed rounds. With threshold 3 even two landed fails cannot have
    // fired, so the check is race-free by construction.
    flag.store(false, Ordering::Relaxed);
    poll_until(
        "first failed probe recorded",
        || async { consec_fails(&engine, CHECK).await >= 1 },
        || events_diag(&events_path),
    )
    .await;
    assert!(
        !has_change(&read_events(&events_path), &target_str, EventChange::Down),
        "no down event may exist below {THRESHOLD} consecutive fails: {:?}",
        read_events(&events_path)
    );

    // --- phase 3: the Nth consecutive fail confirms ONE down.
    poll_until(
        "site down event after the threshold-th consecutive fail",
        || async { has_change(&read_events(&events_path), &target_str, EventChange::Down) },
        || events_diag(&events_path),
    )
    .await;
    {
        let evs = read_events(&events_path);
        let site: Vec<&Event> = evs.iter().filter(|e| e.target == target_str).collect();
        assert_eq!(site.len(), 1, "exactly ONE down, not one per round: {evs:?}");
        assert_eq!(site[0].change, EventChange::Down);
        assert!(
            site[0].detail.as_deref().unwrap_or_default().contains("500"),
            "down detail should carry the HTTP status, got: {:?}",
            site[0].detail
        );
    }

    // --- phase 4: still failing rounds later — exactly one event total
    // (no storm while down).
    poll_until(
        "five failed rounds accumulated while down",
        || async { consec_fails(&engine, CHECK).await >= 5 },
        || events_diag(&events_path),
    )
    .await;
    assert_eq!(
        read_events(&events_path).len(),
        1,
        "repeated fails while down must stay silent: {:?}",
        read_events(&events_path)
    );

    // --- phase 5: first success recovers, exactly one more event.
    flag.store(true, Ordering::Relaxed);
    poll_until(
        "site recovered event after the first success",
        || async {
            last_probe_ok(&engine, CHECK).await
                && has_change(&read_events(&events_path), &target_str, EventChange::Recovered)
        },
        || events_diag(&events_path),
    )
    .await;
    let evs = read_events(&events_path);
    assert_eq!(evs.len(), 2, "the full arc is exactly down+recovered: {evs:?}");
    assert_eq!((evs[0].target.as_str(), evs[0].change), (target_str.as_str(), EventChange::Down));
    assert_eq!((evs[1].target.as_str(), evs[1].change), (target_str.as_str(), EventChange::Recovered));
    assert!(
        evs[1].at_ms >= evs[0].at_ms,
        "recovered cannot predate down: {evs:?}"
    );

    node.kill();
}

// =====================================================================
// 2. Liveness: the peer's death is confirmed from evidence staleness —
//    never instantly. The event timestamp is provably >= last successful
//    contact + t_dead, and it is a single event.
// =====================================================================
#[tokio::test]
async fn peer_death_down_is_evidence_delayed_and_single() {
    const GOSSIP: u64 = 2; // -> t_dead = 3 rounds = 6s
    const THRESHOLD: u32 = 2;
    let t_dead_ms: u64 = GOSSIP * 3_000;

    let dir = tmp("liveness");
    let events_path = dir.join("logs").join("events.jsonl");

    let l1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let l2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p1 = l1.local_addr().unwrap().port();
    let p2 = l2.local_addr().unwrap().port();

    let (mut n1, _s1) = spawn_node(
        mesh_config("m37c-live", 1, &[p1, p2], GOSSIP, THRESHOLD),
        l1,
        Some(events_path.clone()),
        false,
    );
    let (mut n2, _s2) = spawn_node(
        mesh_config("m37c-live", 2, &[p1, p2], GOSSIP, THRESHOLD),
        l2,
        None,
        false,
    );
    let obs = NodeClient::new("m37c-live".into(), 99);

    // Healthy: evidence for node-2 exists and no events may exist.
    poll_until(
        "node-1 holds fresh evidence for node-2",
        || async { seen_at(&obs, &n1.addr, 2).await.is_some() },
        || async { format!("seen: {:?}", obs.state(&n1.addr).await.map(|m| m.seen)) },
    )
    .await;
    assert!(
        read_events(&events_path).is_empty(),
        "healthy peer must not produce events: {:?}",
        read_events(&events_path)
    );

    // Capture the last successful contact, then kill node-2 (whole
    // runtime — every socket drops at once). L is a LOWER bound of the
    // final evidence value (a round may succeed between the read and
    // the kill, which only delays the event further — never earlier).
    let l_before = seen_at(&obs, &n1.addr, 2).await.expect("evidence for node-2");
    n2.kill();

    poll_until(
        "node:2 down event on the survivor",
        || async { has_change(&read_events(&events_path), "node:2", EventChange::Down) },
        || async {
            format!(
                "n1 seen {:?}\n{}",
                obs.state(&n1.addr).await.map(|m| m.seen),
                events_diag(&events_path).await
            )
        },
    )
    .await;

    let evs = read_events(&events_path);
    assert_eq!(evs.len(), 1, "exactly one event for the whole death: {evs:?}");
    assert_eq!((evs[0].target.as_str(), evs[0].change), ("node:2", EventChange::Down));
    // The "not instant" proof: down fires on an observation round where
    // now - last_seen >= t_dead, so the event time is bounded from below
    // by the captured evidence plus the dead window. Same wall clock on
    // both sides, so no skew slack is needed.
    assert!(
        evs[0].at_ms >= l_before + t_dead_ms,
        "down must be evidence-delayed (>= last_seen + t_dead): event {} vs bound {}",
        evs[0].at_ms,
        l_before + t_dead_ms
    );

    n1.kill();
}

// =====================================================================
// 3. File discipline: without enable_events_log the recorder is pure
//    memory — confirmed transitions NEVER create the file. Attaching
//    the sink mid-life starts writing FUTURE transitions only (no
//    retroactive backfill of the already-confirmed down).
// =====================================================================
#[tokio::test]
async fn events_jsonl_only_after_enable_events_log_and_never_backfilled() {
    const THRESHOLD: u32 = 2;
    const CHECK: &str = "late-attach";
    let target_str = format!("site:{CHECK}");

    // Failing from the very first probe: the failing baseline seeds the
    // streak (M3.7-a semantics), so down is confirmed in memory on the
    // threshold-th fail even though the target never worked.
    let flag = Arc::new(AtomicBool::new(false));
    let tl = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_port = tl.local_addr().unwrap().port();
    tokio::spawn(flippable_http(tl, flag.clone()));

    let dir = tmp("noenable");
    let events_path = dir.join("logs").join("events.jsonl");

    let mut cfg = mesh_config("m37c-noenable", 1, &[1, 1], 1, THRESHOLD);
    cfg.nodes.truncate(1);
    cfg.edges.clear();
    cfg.checks = vec![HttpCheckSpec {
        name: CHECK.into(),
        url: format!("http://127.0.0.1:{target_port}/health"),
        expect: Some(200),
        interval: Some(1),
        timeout: Some(1),
    }];
    cfg.recompute_hash();

    // NO enable_events_log: the daemon attaches the sink in cli::run;
    // direct NodeState users (like this test) stay file-free.
    let (mut node, state) = spawn_node(
        cfg,
        TcpListener::bind("127.0.0.1:0").await.unwrap(),
        None,
        false,
    );
    let engine = spawn_check_engine(
        &node,
        &state,
        THRESHOLD,
        state.cfg.read().unwrap().checks.clone(),
    );

    // Down confirmed in memory (fails beyond the threshold) …
    poll_until(
        "fail streak beyond the threshold recorded",
        || async { consec_fails(&engine, CHECK).await >= 3 },
        || events_diag(&events_path),
    )
    .await;
    // … one more full round passes (margin against lazy creation) …
    tokio::time::sleep(Duration::from_millis(1300)).await;
    // … and the file still must not exist at all.
    assert!(
        !events_path.exists(),
        "without enable_events_log the recorder must stay pure memory"
    );

    // Attach the sink MID-LIFE, then recover the target: only the
    // recovered transition may appear — the earlier down is not
    // retroactively written.
    state.enable_events_log(events_path.clone());
    flag.store(true, Ordering::Relaxed);
    poll_until(
        "recovered transition lands in the freshly attached file",
        || async { has_change(&read_events(&events_path), &target_str, EventChange::Recovered) },
        || events_diag(&events_path),
    )
    .await;
    let evs = read_events(&events_path);
    assert_eq!(
        evs.len(),
        1,
        "no retroactive backfill of the pre-attach down: {evs:?}"
    );
    assert_eq!(
        (evs[0].target.as_str(), evs[0].change),
        (target_str.as_str(), EventChange::Recovered)
    );

    node.kill();
}

// =====================================================================
// 4. SSH pair: killing the fake sshd (TCP refused, fast fail) confirms
//    ssh:1->2 down after the threshold; rebinding the port recovers.
// =====================================================================
#[tokio::test]
async fn ssh_pair_down_on_consecutive_refusals_then_recovered() {
    const GOSSIP: u64 = 1;
    const THRESHOLD: u32 = 2;

    // The fake sshd lives in the TEST's runtime so aborting it kills
    // only the sshd — node-2 (and gossip) stays alive, isolating the
    // ssh-pair signal from liveness noise.
    let sshd_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ssh_port = sshd_l.local_addr().unwrap().port();
    let sshd = tokio::spawn(fake_sshd(sshd_l));

    let dir = tmp("sshpair");
    let events_path = dir.join("logs").join("events.jsonl");

    let l1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let l2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p1 = l1.local_addr().unwrap().port();
    let p2 = l2.local_addr().unwrap().port();

    // Only node-2 has an ssh dial: node-1 probes (1->2), node-2 has no
    // probeable peers — node-1's file can only ever hold ssh:1->2.
    let ssh_dial = || SshDial {
        host: "127.0.0.1".into(),
        port: ssh_port,
        user: "deploy".into(),
        forward_host: None,
        forward_port: None,
    };
    let mut cfg1 = mesh_config("m37c-ssh", 1, &[p1, p2], GOSSIP, THRESHOLD);
    cfg1.net.ssh_check_interval_secs = 1;
    cfg1.nodes[1].ssh = Some(ssh_dial());
    cfg1.recompute_hash();
    let mut cfg2 = mesh_config("m37c-ssh", 2, &[p1, p2], GOSSIP, THRESHOLD);
    cfg2.net.ssh_check_interval_secs = 1;
    cfg2.nodes[1].ssh = Some(ssh_dial());
    cfg2.recompute_hash();

    let (mut n1, _s1) = spawn_node(cfg1, l1, Some(events_path.clone()), true);
    let (mut n2, _s2) = spawn_node(cfg2, l2, None, true);
    let obs = NodeClient::new("m37c-ssh".into(), 99);

    // Healthy: the matrix row (1->2) is Ok and no events exist.
    poll_until(
        "ssh row 1->2 recorded as Ok",
        || async {
            matches!(
                ssh_row(&obs, &n1.addr, 1, 2).await,
                Some(p) if matches!(p.outcome, CheckOutcome::Ok { .. })
            )
        },
        || async { format!("ssh rows: {:?}", obs.state(&n1.addr).await.map(|m| m.ssh)) },
    )
    .await;
    assert!(
        read_events(&events_path).is_empty(),
        "healthy ssh pair must not produce events: {:?}",
        read_events(&events_path)
    );

    // Kill the sshd: the port refuses instantly, so the failure rounds
    // are fast; threshold 2 confirms ssh:1->2 down.
    sshd.abort();
    poll_until(
        "ssh:1->2 down event after consecutive refusals",
        || async { has_change(&read_events(&events_path), "ssh:1->2", EventChange::Down) },
        || async {
            format!(
                "ssh rows: {:?}\n{}",
                obs.state(&n1.addr).await.map(|m| m.ssh),
                events_diag(&events_path).await
            )
        },
    )
    .await;
    {
        let evs = read_events(&events_path);
        assert_eq!(evs.len(), 1, "one event so far: {evs:?}");
        assert_eq!((evs[0].target.as_str(), evs[0].change), ("ssh:1->2", EventChange::Down));
        assert!(
            evs[0].detail.as_deref().unwrap_or_default().contains("connect"),
            "down detail should carry the connect failure, got: {:?}",
            evs[0].detail
        );
    }

    // Rebind the same port with a fresh sshd: the next Ok probe recovers.
    let l = TcpListener::bind(("127.0.0.1", ssh_port))
        .await
        .expect("rebind sshd port after the abort");
    tokio::spawn(fake_sshd(l));
    poll_until(
        "ssh:1->2 recovered event after the rebind",
        || async { has_change(&read_events(&events_path), "ssh:1->2", EventChange::Recovered) },
        || async {
            format!(
                "ssh rows: {:?}\n{}",
                obs.state(&n1.addr).await.map(|m| m.ssh),
                events_diag(&events_path).await
            )
        },
    )
    .await;
    let evs = read_events(&events_path);
    let pair: Vec<&Event> = evs.iter().filter(|e| e.target == "ssh:1->2").collect();
    assert_eq!(pair.len(), 2, "exactly down+recovered for the pair: {evs:?}");
    assert_eq!(pair[0].change, EventChange::Down);
    assert_eq!(pair[1].change, EventChange::Recovered);
    // Gossip stayed healthy the whole time: no liveness events may leak
    // into this file.
    assert!(
        evs.iter().all(|e| e.target == "ssh:1->2"),
        "node-2 alive throughout — no node: events expected: {evs:?}"
    );

    n1.kill();
    n2.kill();
}

// =====================================================================
// 5. Anti-storm at boot: configured-but-never-contacted peers produce
//    NO events ever ("never contacted" is not "dead").
// =====================================================================
#[tokio::test]
async fn unseen_peers_produce_no_events_ever() {
    let dir = tmp("unseen");
    let events_path = dir.join("logs").join("events.jsonl");

    // Node 1 with a phantom peer on a port nothing will ever listen on
    // (port 1 refuses instantly — the gossip rounds fail fast).
    let mut cfg = mesh_config("m37c-unseen", 1, &[1, 2], 1, 2);
    cfg.nodes[1].address = Some("127.0.0.1:1".into());
    cfg.recompute_hash();

    let (mut node, _s) = spawn_node(
        cfg,
        TcpListener::bind("127.0.0.1:0").await.unwrap(),
        Some(events_path.clone()),
        false,
    );

    // Let well over five gossip rounds pass (1s cadence); every round
    // fails to reach the phantom, so with threshold 2 a naive
    // implementation would have stormed node:2 downs long ago.
    tokio::time::sleep(Duration::from_millis(5500)).await;
    assert!(
        !events_path.exists(),
        "never-seen peers must stay silent (no file at all), events: {:?}",
        read_events(&events_path)
    );

    node.kill();
}

// =====================================================================
// 6. A healthy mesh writes nothing: evidence keeps refreshing round
//    after round and the event history stays empty.
// =====================================================================
#[tokio::test]
async fn healthy_mesh_writes_no_events() {
    let dir = tmp("healthy");
    let events_path = dir.join("logs").join("events.jsonl");

    let l1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let l2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p1 = l1.local_addr().unwrap().port();
    let p2 = l2.local_addr().unwrap().port();

    let (mut n1, _s1) = spawn_node(
        mesh_config("m37c-healthy", 1, &[p1, p2], 1, 2),
        l1,
        Some(events_path.clone()),
        false,
    );
    let (mut n2, _s2) = spawn_node(
        mesh_config("m37c-healthy", 2, &[p1, p2], 1, 2),
        l2,
        None,
        false,
    );
    let obs = NodeClient::new("m37c-healthy".into(), 99);

    // Observable precondition: evidence for node-2 exists AND has
    // refreshed at least once after the first sighting — two-plus
    // successful contact rounds, not just the first lucky round.
    poll_until(
        "first evidence for node-2",
        || async { seen_at(&obs, &n1.addr, 2).await.is_some() },
        || async { format!("seen: {:?}", obs.state(&n1.addr).await.map(|m| m.seen)) },
    )
    .await;
    let first = seen_at(&obs, &n1.addr, 2).await.expect("evidence");
    poll_until(
        "evidence for node-2 refreshed by a later round",
        || async { seen_at(&obs, &n1.addr, 2).await.is_some_and(|t| t > first) },
        || async { format!("seen: {:?}", obs.state(&n1.addr).await.map(|m| m.seen)) },
    )
    .await;

    // Rounds succeeded repeatedly: the history must be empty (and the
    // file may not even exist — nothing ever transitioned).
    assert!(
        read_events(&events_path).is_empty(),
        "healthy mesh must produce no events: {:?}",
        read_events(&events_path)
    );

    n1.kill();
    n2.kill();
}

// =====================================================================
// 7. A peer that returns after a confirmed death emits recovered —
//    and the whole death+return arc is exactly two events.
// =====================================================================
#[tokio::test]
async fn peer_return_after_death_emits_recovered() {
    const GOSSIP: u64 = 1; // -> t_dead 3s; threshold 2 -> down ~5-7s
    const THRESHOLD: u32 = 2;

    let dir = tmp("return");
    let events_path = dir.join("logs").join("events.jsonl");

    let l1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let l2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p1 = l1.local_addr().unwrap().port();
    let p2 = l2.local_addr().unwrap().port();

    let (mut n1, _s1) = spawn_node(
        mesh_config("m37c-return", 1, &[p1, p2], GOSSIP, THRESHOLD),
        l1,
        Some(events_path.clone()),
        false,
    );
    let (mut n2, _s2) = spawn_node(
        mesh_config("m37c-return", 2, &[p1, p2], GOSSIP, THRESHOLD),
        l2,
        None,
        false,
    );
    let obs = NodeClient::new("m37c-return".into(), 99);

    poll_until(
        "node-1 holds evidence for node-2",
        || async { seen_at(&obs, &n1.addr, 2).await.is_some() },
        || async { format!("seen: {:?}", obs.state(&n1.addr).await.map(|m| m.seen)) },
    )
    .await;

    // Death: kill node-2's runtime and wait for the confirmed down.
    n2.kill();
    poll_until(
        "node:2 down after the death",
        || async { has_change(&read_events(&events_path), "node:2", EventChange::Down) },
        || async {
            format!(
                "n1 seen {:?}\n{}",
                obs.state(&n1.addr).await.map(|m| m.seen),
                events_diag(&events_path).await
            )
        },
    )
    .await;

    // Return: a FRESH node-2 runtime on the same port and config. The
    // survivor's next successful round refreshes the evidence and the
    // first fresh liveness observation emits recovered.
    let l2b = TcpListener::bind(("127.0.0.1", p2))
        .await
        .expect("rebind node-2 port after the runtime died");
    let (mut n2b, _s2b) = spawn_node(
        mesh_config("m37c-return", 2, &[p1, p2], GOSSIP, THRESHOLD),
        l2b,
        None,
        false,
    );

    poll_until(
        "node:2 recovered after the peer returned",
        || async { has_change(&read_events(&events_path), "node:2", EventChange::Recovered) },
        || async {
            format!(
                "n1 seen {:?}\n{}",
                obs.state(&n1.addr).await.map(|m| m.seen),
                events_diag(&events_path).await
            )
        },
    )
    .await;

    let evs = read_events(&events_path);
    let arc: Vec<&Event> = evs.iter().filter(|e| e.target == "node:2").collect();
    assert_eq!(arc.len(), 2, "the whole death+return arc is two events: {evs:?}");
    assert_eq!(arc[0].change, EventChange::Down);
    assert_eq!(arc[1].change, EventChange::Recovered);
    assert!(arc[1].at_ms >= arc[0].at_ms);
    assert!(
        evs.iter().all(|e| e.target == "node:2"),
        "no other targets in this mesh: {evs:?}"
    );

    n1.kill();
    n2b.kill();
}
