//! # VCL CLI
//!
//! Command-line interface for VCL Protocol tunnel management.
//! Provides client and server modes with graceful shutdown, structured logging,
//! and integration with `VCLTunnel` / `VCLConnection` APIs.
//!
//! ## Usage
//!
//! ```bash
//! vcl-cli connect --local 10.0.0.1 --remote 10.0.0.2 --preset mobile
//! vcl-cli server --bind 0.0.0.0:8080
//! VCL_LOG_LEVEL=debug vcl-cli server --bind 127.0.0.1:8080
//! ```

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};
use tokio::signal;
use tokio::time::sleep;
use tracing::{info, warn, error};
use tracing_subscriber::{fmt, EnvFilter};

use vcl_protocol::connection::VCLConnection;
use vcl_protocol::tunnel::{VCLTunnel, TunnelConfig};
use vcl_protocol::config::VCLConfig;
use vcl_protocol::error::VCLError;

/// Log verbosity levels.
#[derive(Debug, Clone, ValueEnum)]
enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    fn to_filter_str(&self) -> &'static str {
        match self {
            LogLevel::Error => "error",
            LogLevel::Warn => "warn,vcl_protocol=warn",
            LogLevel::Info => "info,vcl_protocol=info",
            LogLevel::Debug => "debug,vcl_protocol=debug",
            LogLevel::Trace => "trace,vcl_protocol=trace",
        }
    }
}

/// Network presets.
#[derive(Debug, Clone, ValueEnum)]
enum Preset {
    Mobile,
    Home,
    Corporate,
}

/// Main CLI structure.
#[derive(Parser)]
#[command(
    name = "vcl-cli",
    version = env!("CARGO_PKG_VERSION"),
    about = "VCL Protocol CLI — Secure chained packet transport",
    long_about = "Command-line interface for starting VCL client tunnels and server listeners."
)]
struct Cli {
    /// Global log level.
    #[arg(short = 'l', long, value_enum, default_value_t = LogLevel::Info, env = "VCL_LOG_LEVEL")]
    log_level: LogLevel,

    /// Subcommand.
    #[command(subcommand)]
    command: Commands,
}

/// Available subcommands.
#[derive(Subcommand)]
enum Commands {
    /// Start a client tunnel.
    Connect {
        /// Local TUN IP.
        #[arg(short, long, default_value = "10.0.0.1")]
        local: Ipv4Addr,
        /// Remote gateway IP.
        #[arg(short, long, default_value = "10.0.0.2")]
        remote: Ipv4Addr,
        /// Network preset.
        #[arg(short, long, value_enum, default_value_t = Preset::Mobile)]
        preset: Preset,
        /// DNS upstream.
        #[arg(long, default_value = "1.1.1.1")]
        dns_upstream: String,
        /// Optional TOML config path.
        #[arg(short = 'c', long)]
        config_path: Option<PathBuf>,
    },
    /// Start a server listener.
    Server {
        /// Bind address.
        #[arg(short, long, default_value = "0.0.0.0:8080")]
        bind: String,
    },
}

/// Initialize tracing.
fn init_logging(level: &LogLevel) {
    let filter = EnvFilter::new(level.to_filter_str());
    fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_file(true)
        .with_line_number(true)
        .init();
}

/// Run client tunnel.
async fn run_client(
    local: Ipv4Addr,
    remote: Ipv4Addr,
    preset: Preset,
    dns_upstream: String,
    _config_path: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    info!(
        local = %local,
        remote = %remote,
        preset = ?preset,
        dns = dns_upstream,
        "Initializing client tunnel"
    );

    let config = match preset {
        Preset::Mobile => TunnelConfig::mobile(&local.to_string(), &remote.to_string()),
        Preset::Home => TunnelConfig::home(&local.to_string(), &remote.to_string()),
        Preset::Corporate => TunnelConfig::corporate(&local.to_string(), &remote.to_string()),
    };

    let mut tunnel = VCLTunnel::new(config);

    info!("Tunnel created. Press Ctrl+C to stop.");

    // Graceful shutdown
    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("SIGINT received. Shutting down...");
        }
        _ = async {
            loop {
                sleep(Duration::from_secs(5)).await;
            }
        } => {}
    }

    Ok(())
}

/// Run server listener.
async fn run_server(bind: String) -> Result<(), Box<dyn std::error::Error>> {
    info!(bind = %bind, "Starting VCL server");

    let mut server = VCLConnection::bind(&bind).await.map_err(|e| {
        error!(error = %e, "Failed to bind server");
        e
    })?;

    info!("Server bound. Waiting for handshakes...");

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("SIGINT received. Stopping server...");
                break;
            }
            result = server.accept_handshake() => {
                match result {
                    Ok(()) => info!("Handshake completed"),
                    Err(VCLError::Timeout) => warn!("Handshake timeout"),
                    Err(VCLError::ConnectionClosed) => warn!("Connection closed"),
                    Err(e) => error!(error = %e, "Handshake failed"),
                }
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    init_logging(&cli.log_level);

    match cli.command {
        Commands::Connect { local, remote, preset, dns_upstream, config_path } => {
            run_client(local, remote, preset, dns_upstream, config_path).await
        }
        Commands::Server { bind } => run_server(bind).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn test_cli_parses_connect_defaults() {
        let args = vec!["vcl-cli", "connect"];
        let cli = Cli::try_parse_from(args).unwrap();
        assert!(matches!(cli.command, Commands::Connect { .. }));
    }

    #[test]
    fn test_cli_parses_server_flags() {
        let args = vec!["vcl-cli", "--log-level", "debug", "server", "--bind", "127.0.0.1:9999"];
        let cli = Cli::try_parse_from(args).unwrap();
        assert!(matches!(cli.log_level, LogLevel::Debug));
        if let Commands::Server { bind, .. } = cli.command {
            assert_eq!(bind, "127.0.0.1:9999");
        }
    }

    #[test]
    fn test_cli_command_debug() {
        Cli::command().debug_assert();
    }
}
    }
}
