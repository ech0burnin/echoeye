use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "echoeye",
    version,
    about = "Self-hosted distributed mesh monitoring",
    long_about = "Echoeye — mesh-network monitoring system.\nOne binary acts as either the parent node (web UI + coordinator)\nor a child node. Run `echoeye init <dir>` on the first host to bootstrap a network."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Bootstrap a node: keys, network config
    Init {
        /// Target directory (created if missing)
        dir: String,
    },
    /// Run the daemon (role is decided by the network config)
    Run {
        /// Directory containing network.toml
        dir: String,
    },
    /// Generate an ed25519 keypair and print it
    Keygen,
    /// Deploy a child node to a remote host via SSH (planned for M5)
    Deploy {
        /// Target host (IP or hostname)
        host: String,
        #[arg(long, default_value_t = 22)]
        port: u16,
        #[arg(long, default_value = "root")]
        user: String,
    },
    /// Show network status: nodes, edges, latencies
    Status {
        /// Directory containing network.toml
        #[arg(default_value = ".")]
        dir: String,
    },
    /// Send one test ntfy push via the effective channel (local [ntfy]
    /// or the network channel cache; no daemon needed)
    NtfyTest {
        /// Directory containing network.toml
        #[arg(default_value = ".")]
        dir: String,
    },
    /// Set the mesh-wide delivery channel on THIS node's daemon
    /// (must be the parent node; the next gossip round spreads it)
    ChannelSet {
        /// Directory containing network.toml (of the parent node)
        #[arg(default_value = ".")]
        dir: String,
        /// ntfy server base URL, e.g. https://push.example.tld
        #[arg(long)]
        url: String,
        /// Target topic (deployment secret; masked in all output)
        #[arg(long)]
        topic: String,
        /// Push priority for down events, ntfy 0-5 (default 4)
        #[arg(long)]
        priority_down: Option<u8>,
        /// Push priority for recovered events, ntfy 0-5 (default 3)
        #[arg(long)]
        priority_recovered: Option<u8>,
    },
    /// Clear the mesh-wide delivery channel (alerts off for the mesh;
    /// local [ntfy] overrides keep pushing)
    ChannelClear {
        /// Directory containing network.toml (of the parent node)
        #[arg(default_value = ".")]
        dir: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Init { dir } => echoeye::cli::init(&dir),
        Commands::Run { dir } => echoeye::cli::run(&dir).await,
        Commands::Keygen => echoeye::cli::keygen(),
        Commands::Deploy { .. } => {
            println!("deploy: not implemented yet (planned for M5)");
            Ok(())
        }
        Commands::Status { dir } => echoeye::cli::status(&dir).await,
        Commands::NtfyTest { dir } => echoeye::cli::ntfy_test(&dir).await,
        Commands::ChannelSet { dir, url, topic, priority_down, priority_recovered } => {
            echoeye::cli::channel_set(&dir, &url, &topic, priority_down, priority_recovered).await
        }
        Commands::ChannelClear { dir } => echoeye::cli::channel_clear(&dir).await,
    }
}
