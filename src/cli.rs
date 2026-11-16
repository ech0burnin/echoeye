//! Subcommand implementations (init / run / keygen / status).

use crate::config::NetworkConfig;
use crate::crypto;
use crate::transport::{self, GossipMessage, NodeClient};
use crate::routing;
use anyhow::{Context, Result};
use std::path::Path;
use std::sync::Arc;

pub fn init(dir: &str) -> Result<()> {
    let dir_path = Path::new(dir);
    std::fs::create_dir_all(dir_path).with_context(|| format!("cannot create {dir}"))?;

    let keys = crypto::KeyPair::generate();
    std::fs::write(dir_path.join("node.key"), &keys.secret_hex)?;
    std::fs::write(dir_path.join("node.pub"), &keys.public_hex)?;
    // M2.6: OpenSSH-format public half of the same key — paste into the
    // peer user's authorized_keys for the SSH fallback tunnel (and M5.1 deploy).
    let openssh = crate::tunnel::openssh_public_line(&keys.public_hex)
        .context("cannot derive openssh public line")?;
    std::fs::write(dir_path.join("node.pub.openssh"), &openssh)?;

    let network_secret = crypto::random_hex(32);
    let cfg = NetworkConfig::bootstrap(network_secret, "node-1".to_string());
    cfg.save(&dir_path.join("network.toml"))?;

    std::fs::create_dir_all(dir_path.join("logs"))?;

    println!("initialized node in {dir}");
    println!("node public key: {}", keys.public_hex);
    println!("authorized_keys line: {openssh}");
    println!("listen port: {}", cfg.net.listen_port);
    Ok(())
}

pub async fn run(dir: &str) -> Result<()> {
    let dir_path = Path::new(dir);
    let cfg = NetworkConfig::load(&dir_path.join("network.toml"))
        .with_context(|| format!("network.toml not found in {dir}; run `echoeye init` first"))?;

    let _ = crate::logging::init(&dir_path.join("logs"));
    tracing::info!(
        revision = cfg.revision,
        content_hash = %cfg.content_hash,
        self_name = %cfg.self_name,
        "starting echoeye"
    );

    let state = Arc::new(transport::NodeState::with_persist(
        cfg.clone(),
        dir_path.join("network.toml"),
    ));

    // M3.7: attach the append-only event history BEFORE any monitor loop
    // starts (gossip liveness, check engine, ssh matrix and units all
    // observe into the same recorder) — logs/events.jsonl, rotated at
    // 10 MiB. Until here the recorder is pure memory, which is exactly
    // what direct NodeState users (tests) get.
    state.enable_events_log(dir_path.join("logs").join("events.jsonl"));
    tracing::info!(
        flap_fail_threshold = cfg.net.flap_fail_threshold,
        "event recorder armed (logs/events.jsonl)"
    );

    // M4.4: cold-start channel state from the channel.json cache next
    // to network.toml. The whole mesh may reboot (parent included) —
    // the network channel is runtime-only in memory, without the cache
    // it would be lost forever. Loaded BEFORE the forwarder is wired
    // and before any gossip round, so the first events already resolve
    // against the last known channel; gossip re-delivers and advances
    // from here (strictly-greater merge keeps caches converging).
    {
        let cached = crate::channels::load_cache(dir_path);
        if cached.version > 0 {
            tracing::info!(
                version = cached.version,
                channel = %cached.summary(),
                "channel cache loaded"
            );
            *state.channels.write().unwrap() = cached;
        }
    }

    // M4.1-b/M4.4: the push forwarder. ALWAYS wired now — the
    // effective channel resolves per event (local [ntfy] > network
    // channel > off), so a node without [ntfy] starts pushing the
    // moment gossip delivers the network channel. Wire it BEFORE any
    // monitor loop starts: the tap is an unbounded channel, so
    // confirmed transitions observed during startup queue up and are
    // pushed as soon as the forwarder task gets scheduled — nothing
    // is lost.
    wire_ntfy(&state, &cfg);

    // M2.6: SSH fallback transport — one TunnelManager from our node key,
    // enabled when node.key exists and parses. TOFU pins go next to it.
    let key_path = dir_path.join("node.key");
    if key_path.exists() {
        match std::fs::read_to_string(&key_path)
            .map_err(|e| anyhow::anyhow!("cannot read node.key: {e}"))
            .and_then(|seed| {
                crate::tunnel::TunnelManager::new(
                    seed.trim(),
                    dir_path.join("ssh_known_hosts"),
                )
            }) {
            Ok(tm) => {
                *state.tunnels.lock().await = Some(tm);
                tracing::info!("ssh tunnel manager ready (fallback transport)");
            }
            Err(e) => tracing::warn!(error = %e, "node.key unusable; ssh fallback disabled"),
        }
    }

    // gossip loop: every interval, push our snapshot to all reachable peers,
    // merge their replies, record RTT latencies; deterministic parent
    // election runs after each round (M2.7: the loop lives in
    // transport::spawn_gossip_loop so integration tests drive the same code)
    transport::spawn_gossip_loop(state.clone());

    // M3.1 wiring: scheduled HTTP checks from [[checks]] config.
    // M3.3: EVERY node runs all configured checks locally (config is
    // replicated); finished records feed the gossip-shared probe table.
    if !cfg.checks.is_empty() {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let specs = cfg.checks.clone();
        tracing::info!(count = specs.len(), "check engine starting");

        let sink_state = state.clone();
        let sink_node = cfg.self_id;
        // M3.7: recorder attached — probe outcomes feed the flap
        // automaton, transitions become events (threshold comes from
        // net.flap_fail_threshold via the recorder; the engine's own
        // flap_threshold arg is the legacy no-recorder path only).
        let engine = crate::checks::Engine::new(10, cfg.net.flap_fail_threshold)
            .with_events(state.events.clone())
            .with_sink(std::sync::Arc::new(
            move |rec: &crate::checks::CheckRecord| {
                sink_state.record_own_probe(crate::checks::SiteProbe {
                    check_id: rec.check.clone(),
                    node_id: sink_node,
                    measured_at: rec.at,
                    outcome: rec.outcome.clone(),
                    status: rec.status,
                    ip: rec.ip.clone(),
                });
            },
        ));
        let engine = std::sync::Arc::new(engine);

        tokio::spawn(async move {
            engine.run(specs, shutdown_rx).await;
        });
        // keep the sender alive for the daemon's lifetime; dropping it would
        // make `changed()` return immediately and shut the engine down.
        std::mem::forget(shutdown_tx);
    }

    // M3.2: directed SSH-availability matrix. Every node probes the
    // sshd of every other configured node (TCP + banner, cheap budgets)
    // and shares the rows via gossip; 0 disables the loop. Runtime data
    // only — no persistence, no hash impact.
    crate::sshmatrix::spawn_ssh_matrix_loop(state.clone());

    // M3.5: local docker container monitoring over /var/run/docker.sock.
    // Every node polls its OWN daemon and shares the snapshot via gossip;
    // 0 disables the loop. A host without the socket stays quiet.
    // Runtime data only — no persistence, no hash impact.
    crate::docker::spawn_docker_loop(state.clone());

    // M3.6: periodic systemd unit liveness (`units = [...]` config).
    // Results land in the shared state and ride along with /api/state;
    // runtime data only — no gossip merge, no persistence, no hash impact.
    // M3.7: observations also feed the event recorder (target
    // "unit:<name>") — the pre-M3.7 unconditional "inactive units" warn
    // every 30s is replaced by one down event per unit (warn, written by
    // the recorder) and one recovered (info) when it comes back.
    if !cfg.units.is_empty() {
        let st = state.clone();
        let names = cfg.units.clone();
        tracing::info!(count = names.len(), "unit monitor starting");
        tokio::spawn(async move {
            loop {
                let snapshot = crate::selfstats::collect_units(&names).await;
                let now_ms = crate::checks::chrono_pseudo::Ts::now().unix_ms();
                {
                    let mut recorder = st.events.lock().unwrap();
                    for u in &snapshot {
                        let target = format!("unit:{}", u.name);
                        recorder.observe(&target, u.active, now_ms, None);
                    }
                }
                st.set_units(snapshot);
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            }
        });
    }

    transport::serve(state, cfg.net.listen_port).await
}

/// M4.4: wire the ALWAYS-ON push forwarder to the event recorder's
/// fan-out. Returns the forwarder handle (`Some` unconditionally now).
///
/// The effective channel is resolved PER EVENT from the live node
/// state — local `[ntfy]` section (per-node override) > the network
/// channel delivered by gossip > nothing (legacy silent path: the
/// event is consumed and dropped with a debug line, it is already
/// durable in events.jsonl). This is why the subscription no longer
/// depends on `[ntfy]`: a node without a local section may receive
/// the network channel at any gossip round, and the very next
/// confirmed transition pushes through it — no restart, no rewiring
/// (PLAN M4.2-b "forwarder без рестарта").
///
/// The push title carries the current parent's name as a routing hint
/// (`— parent <name>`) whenever the parent is a node OTHER than this
/// one (see `ntfy::title_for`).
///
/// Called by `run` right after the event log is armed and before any
/// monitor loop, so no confirmed transition can slip past the tap. The
/// returned handle is deliberately dropped by the caller: the forwarder
/// lives for the daemon's lifetime and ends when the recorder (holding
/// the sending side) is dropped at shutdown.
pub fn wire_ntfy(
    state: &Arc<transport::NodeState>,
    cfg: &NetworkConfig,
) -> Option<tokio::task::JoinHandle<()>> {
    // Same lock discipline as every observer of the recorder: a short
    // std-mutex scope with no await inside (subscribe is synchronous).
    let mut rx = state.events.lock().unwrap().subscribe();
    let local = cfg.ntfy.clone();
    let local_for_log = local.clone();
    let self_name = cfg.self_name.clone();
    let self_id = cfg.self_id;
    let st = state.clone();
    let handle = tokio::spawn(async move {
        let http = crate::ntfy::client();
        while let Some(ev) = rx.recv().await {
            // Per-event resolution. All locks are read-locks taken and
            // dropped inside this sync block — nothing held across the
            // send await.
            let (params, parent_name) = {
                let net = st.channels.read().unwrap().clone();
                let Some(params) = crate::channels::resolve(local.as_ref(), &net) else {
                    tracing::debug!(
                        target = %ev.target,
                        "no push channel (no local [ntfy], network channel off) — event stays in events.jsonl"
                    );
                    continue;
                };
                // Parent routing hint: only when the parent is another
                // node (own pushes never self-reference).
                let parent = *st.parent.read().unwrap();
                let parent_name = parent.filter(|p| *p != self_id).and_then(|pid| {
                    st.cfg
                        .read()
                        .unwrap()
                        .nodes
                        .iter()
                        .find(|n| n.id == pid)
                        .map(|n| n.name.clone())
                });
                (params, parent_name)
            };
            let priority = match ev.change {
                crate::events::EventChange::Down => params.priority_down,
                crate::events::EventChange::Recovered => params.priority_recovered,
            };
            let res = crate::ntfy::send(
                &http,
                &params.url,
                &params.topic,
                priority,
                &crate::ntfy::title_for(&ev, &self_name, parent_name.as_deref()),
                &crate::ntfy::body_for(&ev),
                crate::ntfy::tags_for(&ev),
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
    });
    if let Some(ncfg) = &local_for_log {
        // The topic doubles as a push credential — never log it verbatim.
        tracing::info!(
            url = %ncfg.url,
            topic = %mask_topic(&ncfg.topic),
            "ntfy alerts enabled (local [ntfy] overrides the network channel)"
        );
    } else {
        tracing::info!(
            "push forwarder armed without local [ntfy]: waiting for the network channel via gossip"
        );
    }
    Some(handle)
}

/// M4.1-b/M4.4: `echoeye ntfy-test <dir>` — push one test notification
/// through the effective channel so the operator can verify the phone
/// side without waiting for an incident. Reads files directly, no
/// running daemon is required (or contacted): the local `[ntfy]`
/// section wins, else the network channel from the `channel.json`
/// cache (a child node without `[ntfy]` still gets a working check —
/// the cache is refreshed by the daemon on every version advance).
/// Exit code: 0 on a confirmed 2xx delivery, non-zero otherwise (the
/// anyhow Err propagates out of main).
pub async fn ntfy_test(dir: &str) -> Result<()> {
    let dir_path = Path::new(dir);
    let cfg = NetworkConfig::load(&dir_path.join("network.toml"))
        .with_context(|| format!("network.toml not found in {dir}; run `echoeye init` first"))?;
    // Same resolution rule as the live forwarder: local [ntfy] >
    // network channel (cache) > nothing. File-based twin of
    // channels::resolve, so no daemon is needed.
    let (ncfg, source) = match cfg.ntfy.clone() {
        Some(local) => (local, "[ntfy] section"),
        None => {
            let net = crate::channels::load_cache(dir_path);
            let resolved = crate::channels::resolve(None, &net).ok_or_else(|| {
                anyhow::anyhow!(
                    "no [ntfy] section and no network channel in {dir} — \
                     add an [ntfy] section or run `echoeye channel-set` on the parent node"
                )
            })?;
            (resolved, "network channel (channel.json cache)")
        }
    };
    let now = crate::checks::chrono_pseudo::Ts::now();
    let title = format!("echoeye test from {}", cfg.self_name);
    let body = format!(
        "channel check from node {} at unix {} ms",
        cfg.self_name,
        now.unix_ms()
    );
    // Recovery priority (default 3): a channel check must not blare like
    // a confirmed-down siren — high priority stays reserved for real
    // incidents.
    crate::ntfy::send(
        &crate::ntfy::client(),
        &ncfg.url,
        &ncfg.topic,
        ncfg.priority_recovered,
        &title,
        &body,
        &[],
    )
    .await
    .with_context(|| "ntfy test push failed")?;
    println!(
        "sent to {}/{} via {source} — check your phone",
        ncfg.url,
        mask_topic(&ncfg.topic)
    );
    Ok(())
}

/// The ntfy topic doubles as an access credential (anyone who knows it
/// can publish and subscribe): show at most its first 3 chars in logs
/// and CLI output, ellipsis for anything longer.
fn mask_topic(topic: &str) -> String {
    let mut head: String = topic.chars().take(3).collect();
    if topic.chars().count() > 3 {
        head.push('…');
    }
    head
}

/// M4.4: `echoeye channel-set <dir> --url U --topic T` — install the
/// mesh-wide delivery channel by talking to the daemon at
/// 127.0.0.1:<listen_port> (network.toml supplies the secret). The
/// call must land on the PARENT node's daemon (it is the source of
/// truth and the only node allowed to bump the version); a non-parent
/// answers 409 and the CLI surfaces that text. Priorities default to
/// the M4.1 values (4 down / 3 recovered). Output masks the topic.
pub async fn channel_set(
    dir: &str,
    url: &str,
    topic: &str,
    priority_down: Option<u8>,
    priority_recovered: Option<u8>,
) -> Result<()> {
    let cfg = load_cfg_for_api(dir)?;
    let client = NodeClient::new(cfg.auth.network_secret.as_str().into(), cfg.self_id);
    let channel = crate::channels::DeliveryChannel::Ntfy {
        url: url.to_string(),
        topic: topic.to_string(),
        priority_down: priority_down.unwrap_or(crate::ntfy::DEFAULT_PRIORITY_DOWN),
        priority_recovered: priority_recovered.unwrap_or(crate::ntfy::DEFAULT_PRIORITY_RECOVERED),
    };
    let st = client
        .set_channel(&api_addr(&cfg), &channel)
        .await
        .context("channel-set rejected — run it on the parent node with its daemon running")?;
    println!("channel set: {} (version {})", st.summary(), st.version);
    println!("gossip spreads it to every node within one round — no restarts needed");
    Ok(())
}

/// M4.4: `echoeye channel-clear <dir>` — alerts off for the whole mesh
/// (sets `channel: None` at the next version through the parent's
/// daemon; nodes with a local `[ntfy]` override keep pushing by design).
pub async fn channel_clear(dir: &str) -> Result<()> {
    let cfg = load_cfg_for_api(dir)?;
    let client = NodeClient::new(cfg.auth.network_secret.as_str().into(), cfg.self_id);
    let st = client
        .clear_channel(&api_addr(&cfg))
        .await
        .context("channel-clear rejected — run it on the parent node with its daemon running")?;
    println!("channel cleared (version {})", st.version);
    Ok(())
}

/// Shared loader for the API-talking subcommands: config from <dir>,
/// with the same "run init first" hint as every other file-reading
/// command.
fn load_cfg_for_api(dir: &str) -> Result<NetworkConfig> {
    let dir_path = Path::new(dir);
    NetworkConfig::load(&dir_path.join("network.toml"))
        .with_context(|| format!("network.toml not found in {dir}; run `echoeye init` first"))
}

/// Where the API-talking subcommands send requests: the daemon on this
/// very host (channel management is a parent-node operation).
fn api_addr(cfg: &NetworkConfig) -> String {
    format!("127.0.0.1:{}", cfg.net.listen_port)
}

pub fn keygen() -> Result<()> {
    let kp = crypto::KeyPair::generate();
    println!("secret: {}", kp.secret_hex);
    println!("public: {}", kp.public_hex);
    match crate::tunnel::openssh_public_line(&kp.public_hex) {
        Ok(line) => println!("authorized_keys line: {line}"),
        Err(e) => println!("authorized_keys line: (unavailable: {e})"),
    }
    Ok(())
}

/// M4.4: the status line for an offline daemon — honest unknown, the
/// elector's view lives only in the running daemon's memory.
const PARENT_LINE_OFFLINE: &str = "parent: (unknown — daemon offline)";

/// M4.4: render the parent line from a live `/api/health` reply
/// (`parent {id, name}` — name may be null when the parent id is not
/// in this node's node table yet).
fn parent_line_from_health(h: &serde_json::Value) -> String {
    let parent = match h.get("parent") {
        Some(p) if !p.is_null() => p,
        _ => return "parent: (not elected yet)".to_string(),
    };
    let id = parent.get("id").and_then(|v| v.as_u64());
    match (parent.get("name").and_then(|v| v.as_str()), id) {
        (Some(name), Some(id)) => format!("parent: {name} (id {id})"),
        (Some(name), None) => format!("parent: {name}"),
        (None, Some(id)) => format!("parent: (unnamed node id {id})"),
        (None, None) => "parent: (not elected yet)".to_string(),
    }
}

pub async fn status(dir: &str) -> Result<()> {
    let dir_path = Path::new(dir);
    let cfg = NetworkConfig::load(&dir_path.join("network.toml"))
        .with_context(|| format!("network.toml not found in {dir}"))?;

    let client = NodeClient::new(cfg.auth.network_secret.as_str().into(), cfg.self_id);
    let addr = format!("127.0.0.1:{}", cfg.net.listen_port);

    let (msg, live) = match client.state(&addr).await {
        Ok(m) => (m, true),
        Err(_) => (
            GossipMessage {
                from: cfg.self_id,
                revision: cfg.revision,
                nodes: cfg.nodes.clone(),
                edges: cfg.edges.clone(),
                probes: Vec::new(),
                ssh: Vec::new(),
                seen: Vec::new(),
                units: Vec::new(),
                docker: Vec::new(),
                channels: None,
            },
            false,
        ),
    };

    println!("node: {} (id {})", cfg.self_name, cfg.self_id);
    println!("revision {}  hash {}", msg.revision, cfg.content_hash);
    // M2.6: show the same-key authorized_keys line for convenience
    let pub_path = dir_path.join("node.pub");
    if pub_path.exists() {
        if let Ok(hex) = std::fs::read_to_string(&pub_path) {
            if let Ok(line) = crate::tunnel::openssh_public_line(hex.trim()) {
                println!("authorized_keys line: {line}");
            }
        }
    }
    if live {
        println!("source: live daemon at {addr}");
    } else {
        println!("source: local network.toml (daemon not reachable at {addr})");
    }
    // M4.4: who is the parent right now — where the coordinator (and
    // its future web UI) lives, reachable through the tunnel. Live
    // daemon -> /api/health (the elector's current view, no wire
    // change: parent {id,name} was already there); offline -> an
    // honest unknown, never a stale guess.
    let parent_line = match client.health(&addr).await {
        Ok(h) => parent_line_from_health(&h),
        Err(_) => PARENT_LINE_OFFLINE.to_string(),
    };
    println!("{parent_line}");
    println!();
    println!("nodes:");
    for n in &msg.nodes {
        let naddr = n
            .address
            .clone()
            .or_else(|| {
                n.ssh.as_ref().map(|s| {
                    // M2.8 jump entries append the forward target so the
                    // operator sees the hop: ssh user@jumper -> target
                    let jump = match (&s.forward_host, s.forward_port) {
                        (Some(fh), Some(fp)) => format!(" -> {fh}:{fp}"),
                        (Some(fh), None) => format!(" -> {fh}"),
                        _ => String::new(),
                    };
                    format!("ssh {}:{}@{}{jump}", s.user, s.host, s.port)
                })
            })
            .unwrap_or_else(|| "-".into());
        println!("  {}  {}  {}", n.id, n.name, naddr);
    }
    if msg.edges.is_empty() {
        println!("edges: (none yet)");
    } else {
        println!("edges:");
        for e in &msg.edges {
            match e.latency_ms {
                Some(ms) => println!("  {} - {}  {} ms", e.a, e.b, ms),
                None => println!("  {} - {}  ?", e.a, e.b),
            }
        }
    }
    println!();
    // M3.4: self observation (local /proc + statvfs, not part of gossip)
    match crate::selfstats::SelfStats::collect() {
        Ok(s) => {
            println!("self: (collected_at unix {})", s.collected_at);
            println!("  ram   used {:>5.1}%  ({:.1} GiB available / {:.1} GiB total)",
                s.mem.used_pct,
                s.mem.available_kb as f64 / 1024.0 / 1024.0,
                s.mem.total_kb as f64 / 1024.0 / 1024.0);
            println!("  load  {:.2} {:.2} {:.2}  (procs {}/{})",
                s.load.one, s.load.five, s.load.fifteen, s.load.running, s.load.total_procs);
            println!("  disk  used {:>5.1}%  ({:.1} GiB free / {:.1} GiB total)",
                s.disk.used_pct,
                s.disk.free_bytes as f64 / 1024.0 / 1024.0 / 1024.0,
                s.disk.total_bytes as f64 / 1024.0 / 1024.0 / 1024.0);
        }
        Err(e) => println!("self: (unavailable: {e})"),
    }
    // M3.6: systemd unit liveness. Live daemon -> straight from its
    // /api/state reply (the monitor loop keeps it fresh); offline or a
    // daemon that has not collected yet -> probe locally right now.
    if !cfg.units.is_empty() {
        let units = if live && !msg.units.is_empty() {
            msg.units.clone()
        } else {
            crate::selfstats::collect_units(&cfg.units).await
        };
        let rendered: Vec<String> = units
            .iter()
            .map(|u| format!("{} {}", u.name, if u.active { "active" } else { "dead" }))
            .collect();
        println!("  units {}", rendered.join(", "));
    }
    println!();
    let table = routing::RoutingTable::build(cfg.self_id, &msg.nodes, &msg.edges);
    let routes: Vec<&u32> = table.all().keys().collect();
    if routes.is_empty() {
        println!("routes: (no peers reachable yet)");
    } else {
        println!("routes:");
        let mut targets: Vec<_> = table.all().keys().copied().collect();
        targets.sort();
        for t in targets {
            let r = table.route(t).unwrap();
            let path: Vec<String> = r.path.iter().map(|x| x.to_string()).collect();
            println!("  → {}  via {}  {} ms  [{}]", t, r.next_hop, r.cost_ms, path.join("→"));
        }
    }
    println!();
    // M3.3: consolidated site report from the gossip-shared probe table
    println!("sites:");
    if cfg.checks.is_empty() {
        println!("  (none configured)");
    } else {
        let mut probes: crate::sitereport::ProbeTable = crate::sitereport::ProbeTable::new();
        for p in &msg.probes {
            probes.insert((p.check_id.clone(), p.node_id), p.clone());
        }
        let lines = crate::sitereport::report_now(&cfg.checks, &msg.nodes, &probes);
        for l in lines {
            println!("{l}");
        }
        if !live {
            println!("  (daemon offline — no probe data can flow)");
        }
    }
    println!();
    // M3.2: directed SSH-availability matrix, one line per (from -> to)
    let mut matrix: crate::sshmatrix::SshMatrix = crate::sshmatrix::SshMatrix::new();
    for p in &msg.ssh {
        matrix.insert((p.from, p.to), p.clone());
    }
    let interval = if cfg.net.ssh_check_interval_secs == 0 {
        crate::config::DEFAULT_SSH_CHECK_INTERVAL_SECS
    } else {
        cfg.net.ssh_check_interval_secs
    };
    println!("ssh:");
    let lines = crate::sshmatrix::build_ssh_report(
        &msg.nodes,
        &matrix,
        crate::checks::chrono_pseudo::Ts::now().unix_ms(),
        interval,
    );
    if lines.is_empty() {
        println!("  (none configured)");
    } else {
        for l in lines {
            println!("{l}");
        }
    }
    println!();
    // M3.5: docker containers per node. Live daemon -> straight from the
    // gossip-shared table; disabled interval -> explicit marker; a table
    // with no rows yet -> honest "(no data)".
    println!("docker:");
    if cfg.net.docker_check_interval_secs == 0 {
        println!("  (disabled)");
    } else {
        let mut table: crate::docker::DockerTable = crate::docker::DockerTable::new();
        for p in &msg.docker {
            table.insert(p.node_id, p.clone());
        }
        let lines = crate::docker::build_docker_report(
            &msg.nodes,
            &table,
            crate::checks::chrono_pseudo::Ts::now().unix_ms(),
        );
        if lines.is_empty() {
            println!("  (no data)");
        } else {
            for l in lines {
                println!("{l}");
            }
        }
    }
    println!();
    // M3.7: tail of this node's own event history — confirmed state
    // transitions of what THIS node observes (sites, ssh pairs, peer
    // liveness, units). Best effort: missing/empty file = no events yet;
    // a stray non-JSON line falls back to raw text instead of failing.
    println!("events:");
    let events_path = dir_path.join("logs").join("events.jsonl");
    let tail: Vec<String> = std::fs::read_to_string(&events_path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(str::to_string)
        .collect();
    if tail.is_empty() {
        println!("  (no events yet)");
    } else {
        for line in tail.iter().rev().take(5).rev() {
            let rendered = match serde_json::from_str::<crate::events::Event>(line) {
                Ok(ev) => {
                    let change = match ev.change {
                        crate::events::EventChange::Down => "down",
                        crate::events::EventChange::Recovered => "recovered",
                    };
                    format!(
                        "{}  {:<24}  {}  {}",
                        ev.at_ms,
                        ev.target,
                        change,
                        ev.detail.as_deref().unwrap_or("")
                    )
                    .trim_end()
                    .to_string()
                }
                Err(_) => line.clone(),
            };
            println!("  {rendered}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("em-m37b-cli-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[tokio::test]
    async fn status_events_section_tolerates_missing_and_present_file() {
        // No daemon on a privileged port: instant connection refusal, so
        // status takes its "daemon offline" path and must still render
        // the events section — with no events.jsonl at all.
        let mut cfg = NetworkConfig::bootstrap("s".into(), "n1".into());
        cfg.net.listen_port = 1;
        let dir = tmp("missing");
        cfg.save(&dir.join("network.toml")).unwrap();
        assert!(status(dir.to_str().unwrap()).await.is_ok(), "missing events file must not fail status");

        // With a populated events file (plus one junk line to prove the
        // best-effort parse) status must succeed as well.
        let dir2 = tmp("present");
        std::fs::create_dir_all(dir2.join("logs")).unwrap();
        cfg.save(&dir2.join("network.toml")).unwrap();
        std::fs::write(
            dir2.join("logs").join("events.jsonl"),
            concat!(
                "{\"at_ms\":1,\"target\":\"site:x\",\"change\":\"down\",\"detail\":null}\n",
                "{\"at_ms\":2,\"target\":\"node:2\",\"change\":\"recovered\",\"detail\":null}\n",
                "not-json-at-all\n",
            ),
        )
        .unwrap();
        assert!(status(dir2.to_str().unwrap()).await.is_ok(), "events file (with junk line) must not fail status");
    }

    // ---------- M4.1-b: ntfy wiring + ntfy-test CLI ----------

    /// Minimal fake ntfy (real axum on loopback), same shape as the
    /// harness in ntfy.rs: capture (path, decoded JSON body) of every
    /// POST on the topic route.
    async fn spawn_fake_ntfy(
        status: axum::http::StatusCode,
    ) -> (u16, Arc<std::sync::Mutex<Vec<(String, serde_json::Value)>>>) {
        let sink: Arc<std::sync::Mutex<Vec<(String, serde_json::Value)>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink_route = sink.clone();
        let routes = axum::Router::new().route(
            "/test-topic",
            axum::routing::post(move |uri: axum::http::Uri, body: String| {
                let sink = sink_route.clone();
                async move {
                    sink.lock().unwrap().push((
                        uri.path().to_string(),
                        serde_json::from_str(&body).unwrap_or(serde_json::Value::Null),
                    ));
                    status
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, routes).await.unwrap() });
        (port, sink)
    }

    /// Poll with an ASYNC sleep: the forwarder task shares this
    /// current-thread runtime, a blocking std sleep would starve it
    /// (lesson from M4.1-a).
    async fn wait_for<F: Fn() -> bool>(cond: F) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !cond() {
            assert!(std::time::Instant::now() < deadline, "condition not met within 10s");
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    fn ntfy_cfg(port: u16) -> crate::ntfy::NtfySection {
        crate::ntfy::NtfySection {
            url: format!("http://127.0.0.1:{port}"),
            topic: "test-topic".into(),
            priority_down: 4,
            priority_recovered: 3,
        }
    }

    #[tokio::test]
    async fn wire_ntfy_without_channel_stays_silent() {
        // No local [ntfy] AND no network channel: the forwarder is
        // STILL wired (M4.4 always-subscribe), consumes the event and
        // pushes nothing — the legacy silent behavior by resolution,
        // not by absence of a subscription.
        let (port, sink) = spawn_fake_ntfy(axum::http::StatusCode::OK).await;
        let mut cfg = NetworkConfig::bootstrap("s".into(), "n1".into());
        cfg.net.flap_fail_threshold = 2;
        assert!(cfg.ntfy.is_none());
        // Point a WOULD-BE network channel at the fake so any bug in
        // the resolution would land there — but never install it.
        let state = Arc::new(transport::NodeState::new(cfg.clone()));

        let handle = wire_ntfy(&state, &cfg)
            .expect("M4.4: the forwarder is always wired (Some)");
        assert!(!handle.is_finished());

        // Drive the recorder to a confirmed down; a second subscriber
        // (our own tap) observes the event — an observable precondition
        // for "the forwarder saw it too and chose silence".
        let mut my_rx = state.events.lock().unwrap().subscribe();
        {
            let mut rec = state.events.lock().unwrap();
            rec.observe("site:x", true, 1, None);
            rec.observe("site:x", false, 2, Some("HTTP 500"));
            rec.observe("site:x", false, 3, Some("HTTP 500"));
        }
        let seen = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            my_rx.recv(),
        )
        .await
        .expect("the confirmed event fans out to every subscriber")
        .expect("recorder tap stays open");
        assert_eq!(seen.target, "site:x");
        // Grace window for a (wrong) push to land, then the verdict.
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        assert!(
            sink.lock().unwrap().is_empty(),
            "no channel => no push, ever: {:?}",
            sink.lock().unwrap()
        );
        assert!(!handle.is_finished(), "the forwarder survives silence");
        let _ = port;
    }

    #[tokio::test]
    async fn wire_ntfy_picks_up_network_channel_without_restart() {
        // THE M4.4 proof: the node starts with NO channel (event
        // consumed silently), the network channel arrives mid-flight
        // (gossip merge — here: apply_channel), and the NEXT confirmed
        // event pushes through it. No task restarted, no rewiring.
        let (port, sink) = spawn_fake_ntfy(axum::http::StatusCode::OK).await;
        let mut cfg = NetworkConfig::bootstrap("s".into(), "n1".into());
        cfg.net.flap_fail_threshold = 2;
        let state = Arc::new(transport::NodeState::new(cfg.clone()));
        let _ = wire_ntfy(&state, &cfg);

        // Event #1 (down) with no channel: silent, observed via our tap.
        let mut my_rx = state.events.lock().unwrap().subscribe();
        {
            let mut rec = state.events.lock().unwrap();
            rec.observe("site:x", true, 1, None);
            rec.observe("site:x", false, 2, Some("HTTP 500"));
            rec.observe("site:x", false, 3, Some("HTTP 500"));
        }
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), my_rx.recv())
            .await
            .expect("down event fanned out");
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        assert!(sink.lock().unwrap().is_empty(), "no channel yet => no push");

        // The network channel arrives (as a gossip merge would deliver).
        state.apply_channel(Some(&crate::channels::ChannelState {
            version: 1,
            channel: Some(crate::channels::DeliveryChannel::Ntfy {
                url: format!("http://127.0.0.1:{port}"),
                topic: "test-topic".into(),
                priority_down: 4,
                priority_recovered: 3,
            }),
        }));

        // Event #2 (recovered) pushes through the fresh channel; no
        // parent elected => no suffix in the title.
        {
            let mut rec = state.events.lock().unwrap();
            rec.observe("site:x", true, 4, Some("200 OK"));
        }
        wait_for(|| !sink.lock().unwrap().is_empty()).await;
        let got = { sink.lock().unwrap().pop().unwrap() };
        assert_eq!(got.0, "/test-topic", "the NETWORK channel's endpoint");
        assert_eq!(got.1["title"], "echoeye n1: RECOVERED site:x");
        assert_eq!(got.1["priority"], 3);
    }

    #[tokio::test]
    async fn wire_ntfy_local_section_overrides_network_channel() {
        // Local [ntfy] beats the network channel (per-node override):
        // two fakes, local -> fake1, network -> fake2; the push must
        // land ONLY on fake1.
        let (port1, sink1) = spawn_fake_ntfy(axum::http::StatusCode::OK).await;
        let (port2, sink2) = spawn_fake_ntfy(axum::http::StatusCode::OK).await;
        let mut cfg = NetworkConfig::bootstrap("s".into(), "n1".into());
        cfg.net.flap_fail_threshold = 2;
        cfg.ntfy = Some(ntfy_cfg(port1));
        let state = Arc::new(transport::NodeState::new(cfg.clone()));
        let _ = wire_ntfy(&state, &cfg);
        // A LIVE network channel exists and points elsewhere.
        state.apply_channel(Some(&crate::channels::ChannelState {
            version: 7,
            channel: Some(crate::channels::DeliveryChannel::Ntfy {
                url: format!("http://127.0.0.1:{port2}"),
                topic: "test-topic".into(),
                priority_down: 4,
                priority_recovered: 3,
            }),
        }));

        {
            let mut rec = state.events.lock().unwrap();
            rec.observe("site:x", true, 1, None);
            rec.observe("site:x", false, 2, Some("HTTP 500"));
            rec.observe("site:x", false, 3, Some("HTTP 500"));
        }
        wait_for(|| !sink1.lock().unwrap().is_empty()).await;
        let got = { sink1.lock().unwrap().pop().unwrap() };
        assert_eq!(got.0, "/test-topic");
        assert_eq!(got.1["title"], "echoeye n1: DOWN site:x");
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        assert!(
            sink2.lock().unwrap().is_empty(),
            "the network channel must stay untouched under a local override: {:?}",
            sink2.lock().unwrap()
        );
    }

    #[tokio::test]
    async fn wire_ntfy_title_carries_parent_only_when_other_node() {
        let (port, sink) = spawn_fake_ntfy(axum::http::StatusCode::OK).await;
        let mut cfg = NetworkConfig::bootstrap("s".into(), "n1".into());
        cfg.net.flap_fail_threshold = 2;
        cfg.ntfy = Some(ntfy_cfg(port));
        // A second node exists and is the parent.
        cfg.nodes.push(crate::config::NodeEntry {
            id: 2,
            name: "d1337".into(),
            public_key: None,
            address: None,
            ssh: None,
        });
        cfg.recompute_hash();
        let state = Arc::new(transport::NodeState::new(cfg.clone()));
        let _ = wire_ntfy(&state, &cfg);
        *state.parent.write().unwrap() = Some(2);

        {
            let mut rec = state.events.lock().unwrap();
            rec.observe("site:x", true, 1, None);
            rec.observe("site:x", false, 2, Some("HTTP 500"));
            rec.observe("site:x", false, 3, Some("HTTP 500"));
        }
        wait_for(|| !sink.lock().unwrap().is_empty()).await;
        let down = { sink.lock().unwrap().pop().unwrap() };
        assert_eq!(
            down.1["title"],
            "echoeye n1: DOWN site:x — parent d1337",
            "push from a CHILD carries the parent routing hint"
        );

        // THIS node becomes the parent: its own pushes drop the suffix.
        *state.parent.write().unwrap() = Some(1);
        {
            let mut rec = state.events.lock().unwrap();
            rec.observe("site:x", true, 4, Some("200 OK"));
        }
        wait_for(|| !sink.lock().unwrap().is_empty()).await;
        let rec_ev = { sink.lock().unwrap().pop().unwrap() };
        assert_eq!(
            rec_ev.1["title"],
            "echoeye n1: RECOVERED site:x",
            "the parent never self-references in its own title"
        );
    }

    #[tokio::test]
    async fn wire_ntfy_subscribes_recorder_and_pushes_down_event() {
        let (port, sink) = spawn_fake_ntfy(axum::http::StatusCode::OK).await;
        let mut cfg = NetworkConfig::bootstrap("s".into(), "n1".into());
        cfg.net.flap_fail_threshold = 2;
        cfg.ntfy = Some(ntfy_cfg(port));
        let state = Arc::new(transport::NodeState::new(cfg.clone()));

        let handle = wire_ntfy(&state, &cfg).expect("[ntfy] configured => forwarder wired");
        assert!(!handle.is_finished(), "forwarder must stay alive");

        // Drive the recorder exactly like the monitor loops do (short
        // std-mutex scope, no await inside): up baseline, then two misses
        // — threshold 2 confirms the down on the second, which must flow
        // through the tap to the fake ntfy.
        {
            let mut rec = state.events.lock().unwrap();
            rec.observe("site:x", true, 1, None);
            rec.observe("site:x", false, 2, Some("HTTP 500"));
            rec.observe("site:x", false, 3, Some("HTTP 500"));
        }
        wait_for(|| !sink.lock().unwrap().is_empty()).await;
        let got = { sink.lock().unwrap().pop().unwrap() };
        assert_eq!(got.0, "/test-topic");
        assert_eq!(got.1["title"], "echoeye n1: DOWN site:x");
        assert_eq!(got.1["priority"], 4);
        assert_eq!(got.1["tags"], serde_json::json!(["rotating_light"]));
        assert_eq!(got.1["message"], "HTTP 500");
    }

    #[tokio::test]
    async fn ntfy_test_without_section_fails_with_clear_error() {
        let cfg = NetworkConfig::bootstrap("s".into(), "n1".into());
        let dir = tmp("ntfy-test-missing");
        cfg.save(&dir.join("network.toml")).unwrap();
        let err = ntfy_test(dir.to_str().unwrap())
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("[ntfy]"),
            "error must point at the missing section: {err}"
        );
        assert!(
            err.to_string().contains("channel-set"),
            "error must hint the M4.4 way out: {err}"
        );
    }

    #[tokio::test]
    async fn ntfy_test_falls_back_to_channel_cache() {
        // M4.4: a child node without [ntfy] carries the network channel
        // in channel.json — ntfy-test must check THAT channel too
        // (files only, no daemon involved).
        let (port, sink) = spawn_fake_ntfy(axum::http::StatusCode::OK).await;
        let cfg = NetworkConfig::bootstrap("s".into(), "n1".into());
        assert!(cfg.ntfy.is_none());
        let dir = tmp("ntfy-test-cache");
        cfg.save(&dir.join("network.toml")).unwrap();
        crate::channels::save_cache(
            &dir,
            &crate::channels::ChannelState {
                version: 3,
                channel: Some(crate::channels::DeliveryChannel::Ntfy {
                    url: format!("http://127.0.0.1:{port}"),
                    topic: "test-topic".into(),
                    priority_down: 4,
                    priority_recovered: 3,
                }),
            },
        );

        ntfy_test(dir.to_str().unwrap())
            .await
            .expect("the cached network channel answers the check");
        wait_for(|| !sink.lock().unwrap().is_empty()).await;
        let got = { sink.lock().unwrap().pop().unwrap() };
        assert_eq!(got.0, "/test-topic", "push went through the CACHED channel");
        assert_eq!(got.1["title"], "echoeye test from n1");
    }

    // ---------- M4.4: channel-set / channel-clear CLI ----------

    /// A live router standing in for the parent daemon, plus the dir
    /// whose network.toml points the CLI at it (secret + listen_port).
    async fn spawn_parent_api_dir(
        tag: &str,
        elect_parent: bool,
    ) -> (
        Arc<transport::NodeState>,
        std::path::PathBuf,
    ) {
        let mut cfg = NetworkConfig::bootstrap("s".into(), "n1".into());
        cfg.self_id = 1;
        let state = Arc::new(transport::NodeState::new(cfg.clone()));
        if elect_parent {
            *state.parent.write().unwrap() = Some(1);
        }
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        cfg.net.listen_port = l.local_addr().unwrap().port();
        cfg.recompute_hash();
        let dir = tmp(tag);
        cfg.save(&dir.join("network.toml")).unwrap();
        let s = state.clone();
        tokio::spawn(async move { axum::serve(l, transport::router(s)).await.unwrap() });
        (state, dir)
    }

    #[tokio::test]
    async fn channel_set_and_clear_cli_talk_to_the_parent_daemon() {
        let (state, dir) = spawn_parent_api_dir("chan-set", true).await;

        channel_set(
            dir.to_str().unwrap(),
            "http://127.0.0.1:9999",
            "test-topic",
            None,
            None,
        )
        .await
        .expect("parent daemon accepts the set");
        {
            let st = state.channels.read().unwrap();
            assert_eq!(st.version, 1);
            assert_eq!(st.channel.as_ref().unwrap().to_ntfy_params().topic, "test-topic");
        }

        // Replace: version bumps, topic swaps.
        channel_set(
            dir.to_str().unwrap(),
            "http://127.0.0.1:9999",
            "test-topic-2",
            Some(5),
            Some(2),
        )
        .await
        .expect("parent daemon accepts the replace");
        {
            let st = state.channels.read().unwrap();
            assert_eq!(st.version, 2);
            let params = st.channel.as_ref().unwrap().to_ntfy_params();
            assert_eq!(params.topic, "test-topic-2");
            assert_eq!(params.priority_down, 5, "explicit priorities pass through");
            assert_eq!(params.priority_recovered, 2);
        }

        channel_clear(dir.to_str().unwrap())
            .await
            .expect("parent daemon accepts the clear");
        let st = state.channels.read().unwrap();
        assert_eq!((st.version, st.channel.clone()), (3, None));
    }

    #[tokio::test]
    async fn channel_set_cli_fails_clearly_on_non_parent() {
        // Daemon alive but NOT the parent -> 409 -> the CLI surfaces
        // the explanatory body, exit code non-zero.
        let (_state, dir) = spawn_parent_api_dir("chan-nonparent", false).await;
        let err = channel_set(dir.to_str().unwrap(), "http://127.0.0.1:9999", "test-topic", None, None)
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("parent node"),
            "the 409 body must reach the operator: {msg}"
        );
    }

    #[tokio::test]
    async fn channel_set_cli_fails_without_daemon() {
        // No daemon on a privileged port: instant refusal, clear error.
        let mut cfg = NetworkConfig::bootstrap("s".into(), "n1".into());
        cfg.net.listen_port = 1;
        let dir = tmp("chan-nodead");
        cfg.save(&dir.join("network.toml")).unwrap();
        assert!(channel_set(dir.to_str().unwrap(), "http://127.0.0.1:9999", "test-topic", None, None)
            .await
            .is_err());
    }

    // ---------- M4.4: parent line in status ----------

    #[test]
    fn parent_line_renders_live_and_offline_variants() {
        // Live with a known parent: name + id.
        let h = serde_json::json!({
            "status": "ok", "node": "n2",
            "parent": {"id": 1, "name": "d1337", "addr": "10.0.0.1:8686"}
        });
        assert_eq!(parent_line_from_health(&h), "parent: d1337 (id 1)");
        // Live, election not settled yet (parent: null).
        let h = serde_json::json!({"status": "ok", "node": "n1", "parent": null});
        assert_eq!(parent_line_from_health(&h), "parent: (not elected yet)");
        // Live, parent id known but not in the node table (name null).
        let h = serde_json::json!({
            "status": "ok", "node": "n2",
            "parent": {"id": 7, "name": null, "addr": null}
        });
        assert_eq!(parent_line_from_health(&h), "parent: (unnamed node id 7)");
        // Daemon offline: the honest constant (asserted verbatim — it
        // is what status prints next to "source: local network.toml").
        assert_eq!(PARENT_LINE_OFFLINE, "parent: (unknown — daemon offline)");
    }

    #[tokio::test]
    async fn ntfy_test_pushes_and_succeeds_against_fake_server() {
        let (port, sink) = spawn_fake_ntfy(axum::http::StatusCode::OK).await;
        let mut cfg = NetworkConfig::bootstrap("s".into(), "n1".into());
        cfg.ntfy = Some(ntfy_cfg(port));
        let dir = tmp("ntfy-test-ok");
        cfg.save(&dir.join("network.toml")).unwrap();

        // Ok(()) is what main turns into exit code 0.
        ntfy_test(dir.to_str().unwrap())
            .await
            .expect("2xx from ntfy => Ok (exit 0)");
        wait_for(|| !sink.lock().unwrap().is_empty()).await;
        let got = { sink.lock().unwrap().pop().unwrap() };
        assert_eq!(got.0, "/test-topic");
        assert_eq!(got.1["title"], "echoeye test from n1");
        assert!(
            got.1["message"].as_str().unwrap().contains("node n1"),
            "body must carry the node name: {}",
            got.1["message"]
        );
        assert_eq!(got.1["priority"], 3, "channel check, not an alarm");
    }

    #[tokio::test]
    async fn ntfy_test_server_500_is_err_nonzero_exit_path() {
        let (port, _sink) = spawn_fake_ntfy(axum::http::StatusCode::INTERNAL_SERVER_ERROR).await;
        let mut cfg = NetworkConfig::bootstrap("s".into(), "n1".into());
        cfg.ntfy = Some(ntfy_cfg(port));
        let dir = tmp("ntfy-test-500");
        cfg.save(&dir.join("network.toml")).unwrap();
        // Err propagates out of main => non-zero exit code.
        assert!(
            ntfy_test(dir.to_str().unwrap()).await.is_err(),
            "5xx from the ntfy server must fail the command"
        );
    }

    #[test]
    fn mask_topic_keeps_first_three_chars_only() {
        assert_eq!(mask_topic("topsecret-topic-9"), "top…");
        assert_eq!(mask_topic("abcd"), "abc…");
        assert_eq!(mask_topic("abc"), "abc");
        assert_eq!(mask_topic(""), "");
    }
}
