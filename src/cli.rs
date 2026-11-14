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
}
