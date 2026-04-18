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
//! vcl-cli server --bind 0.0.0.0:8080 --timeout 300
//! vcl-cli --log-level debug server --bind 127.0.0.1:8080
//! ```

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};
use tokio::signal;
use tokio::time::sleep;
use tracing::{info, warn, error, debug};
use tracing_subscriber::{fmt, EnvFilter};

use vcl_protocol::connection::VCLConnection;
use vcl_protocol::tunnel::{VCLTunnel, TunnelConfig};
use vcl_protocol::config::VCLConfig;
use vcl_protocol::error::VCLError;

/// Log verbosity levels supported by the CLI.
#[derive(Debug, Clone, ValueEnum)]
enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Error => write!(f, "error"),
            LogLevel::Warn => write!(f, "warn"),
            LogLevel::Info => write!(f, "info"),
            LogLevel::Debug => write!(f, "debug"),
            LogLevel::Trace => write!(f, "trace"),
        }
    }
}

/// Network presets for tunnel configuration.
#[derive(Debug, Clone, ValueEnum)]
enum Preset {
    Mobile,
    Home,
    Corporate,
}

/// Main CLI entry point structure.
#[derive(Parser)]
#[command(
    name = "vcl-cli",
    version = env!("CARGO_PKG_VERSION"),
    about = "VCL Protocol CLI — Secure chained packet transport",
    long_about = "Command-line interface for starting VCL client tunnels and server listeners with graceful shutdown and structured logging."
)]
struct Cli {
    /// Global log level.
    #[arg(short = 'l', long, value_enum, default_value_t = LogLevel::Info, env = "VCL_LOG_LEVEL")]
    log_level: LogLevel,

    /// Subcommand to execute.
    #[command(subcommand)]
    command: Commands,
}

/// Available CLI subcommands.
#[derive(Subcommand)]
enum Commands {
    /// Start a client tunnel connection.
    Connect {
        /// Local TUN interface IP address.
        #[arg(short, long, default_value = "10.0.0.1")]
        local: Ipv4Addr,
        /// Remote gateway IP address.
        #[arg(short, long, default_value = "10.0.0.2")]
        remote: Ipv4Addr,
        /// Network preset for tunnel behavior.
        #[arg(short, long, value_enum, default_value_t = Preset::Mobile)]
        preset: Preset,
        /// Primary DNS upstream server.
        #[arg(long, default_value = "1.1.1.1")]
        dns_upstream: String,
        /// Path to optional TOML configuration file.
        #[arg(short = 'c', long)]
        config_path: Option<PathBuf>,
        /// Server bind address for underlying VCL connection.
        #[arg(short = 'b', long, default_value = "0.0.0.0:0")]
        server_bind: String,
    },
    /// Start a VCL server listener.
    Server {
        /// Bind address for the server.
        #[arg(short, long, default_value = "0.0.0.0:8080")]
        bind: String,
        /// Inactivity timeout in seconds.
        #[arg(short = 't', long, default_value_t = 300)]
        timeout: u64,
        /// Transport mode (udp, tcp, auto).
        #[arg(short = 'm', long, default_value = "udp")]
        transport: String,
    },
}

/// Initialize the tracing subscriber with the selected log level.
fn init_logging(level: &LogLevel) {
    let filter = match level {
        LogLevel::Error => "error",
        LogLevel::Warn => "warn,vcl_protocol=warn",
        LogLevel::Info => "info,vcl_protocol=info",
        LogLevel::Debug => "debug,vcl_protocol=debug",
        LogLevel::Trace => "trace,vcl_protocol=trace",
    };

    fmt()
        .with_env_filter(EnvFilter::new(filter))
        .with_target(true)
        .with_thread_ids(false)
        .with_file(true)
        .with_line_number(true)
        .init();
}

/// Run the client tunnel lifecycle.
async fn run_client(
    local: Ipv4Addr,
    remote: Ipv4Addr,
    preset: Preset,
    dns_upstream: String,
    _config_path: Option<PathBuf>,
    server_bind: String,
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

    // In a full implementation, config_path would override fields here via serde_toml.
    // For now, we rely on preset defaults + CLI overrides.

    let mut tunnel = VCLTunnel::with_config(config).map_err(|e| {
        error!(error = %e, "Failed to create tunnel");
        e
    })?;

    info!("Tunnel interface created. Waiting for connections...");

    // Graceful shutdown loop
    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("Received SIGINT. Initiating graceful shutdown...");
        }
        result = async {
            // Simulate tunnel event loop or block on tunnel events
            loop {
                sleep(Duration::from_secs(5)).await;
                debug!("Tunnel heartbeat alive");
            }
        } => {
            let _ = result;
        }
    }

    info!("Shutting down tunnel gracefully...");
    // tunnel.stop() would be called here in v1.6.0+
    Ok(())
}

/// Run the server listener lifecycle.
async fn run_server(
    bind: String,
    timeout: u64,
    transport: String,
) -> Result<(), Box<dyn std::error::Error>> {
    info!(bind = %bind, timeout, transport = %transport, "Initializing VCL server");

    let config = VCLConfig::auto().with_timeout(timeout);
    let mut server = VCLConnection::bind_with_config(&bind, config).await.map_err(|e| {
        error!(error = %e, "Failed to bind server");
        e
    })?;

    info!("Server bound. Waiting for incoming handshakes...");

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Received SIGINT. Stopping server...");
                break;
            }
            result = server.accept_handshake() => {
                match result {
                    Ok(()) => info!("Client handshake completed successfully"),
                    Err(VCLError::Timeout) => warn!("Client handshake timed out"),
                    Err(VCLError::ConnectionClosed) => warn!("Connection closed during handshake"),
                    Err(e) => error!(error = %e, "Handshake failed"),
                }
            }
        }
    }

    info!("Server stopped. Cleaning up resources...");
    Ok(())
}

/// CLI entry point.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    init_logging(&cli.log_level);

    let result = match cli.command {
        Commands::Connect { local, remote, preset, dns_upstream, config_path, server_bind } => {
            run_client(local, remote, preset, dns_upstream, config_path, server_bind).await
        }
        Commands::Server { bind, timeout, transport } => {
            run_server(bind, timeout, transport).await
        }
    };

    match result {
        Ok(()) => {
            info!("CLI exited cleanly");
            Ok(())
        }
        Err(e) => {
            error!(error = %e, "CLI exited with error");
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn test_cli_parses_client_defaults() {
        let args = vec!["vcl-cli", "connect"];
        let cli = Cli::try_parse_from(args).unwrap();
        assert!(matches!(cli.command, Commands::Connect { .. }));
        if let Commands::Connect { local, remote, preset, .. } = cli.command {
            assert_eq!(local, Ipv4Addr::new(10, 0, 0, 1));
            assert_eq!(remote, Ipv4Addr::new(10, 0, 0, 2));
            assert!(matches!(preset, Preset::Mobile));
        }
    }

    #[test]
    fn test_cli_parses_server_flags() {
        let args = vec![
            "vcl-cli", "--log-level", "debug", "server",
            "--bind", "127.0.0.1:9999", "--timeout", "120",
        ];
        let cli = Cli::try_parse_from(args).unwrap();
        assert!(matches!(cli.log_level, LogLevel::Debug));
        if let Commands::Server { bind, timeout, .. } = cli.command {
            assert_eq!(bind, "127.0.0.1:9999");
            assert_eq!(timeout, 120);
        }
    }

    #[test]
    fn test_cli_requires_subcommand() {
        let args = vec!["vcl-cli"];
        assert!(Cli::try_parse_from(args).is_err());
    }

    #[test]
    fn test_cli_command_factory() {
        Cli::command().debug_assert();
    }
}
