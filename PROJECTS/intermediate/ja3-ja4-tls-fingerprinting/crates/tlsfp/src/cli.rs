// ©AngelaMos | 2026
// cli.rs

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use tlsfp_core::{PcapFileSource, Pipeline, PipelineConfig};

/// JA3/JA4 TLS fingerprinting tool.
///
/// Fingerprints TLS clients and servers from live capture or packet captures,
/// matches them against a local intelligence database, and flags anomalies such
/// as a fingerprint that disagrees with its own User-Agent.
#[derive(Debug, Parser)]
#[command(name = "tlsfp", version, about, long_about = None)]
pub struct Cli {
    /// Increase log verbosity (repeat for more detail).
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Fingerprint every TLS and QUIC handshake in a packet capture file.
    Pcap {
        /// Path to a pcap or pcapng file.
        path: std::path::PathBuf,

        /// Emit one JSON object per event instead of readable lines.
        #[arg(long)]
        json: bool,
    },

    /// Capture live from a network interface and fingerprint in real time.
    Live {
        /// Interface name, for example eth0.
        interface: String,
    },

    /// Serve the web dashboard and HTTP API.
    Serve {
        /// Address to bind, for example 127.0.0.1:8080.
        #[arg(default_value = "127.0.0.1:8080")]
        bind: String,
    },
}

impl Cli {
    pub fn init_tracing(&self) {
        let default = match self.verbose {
            0 => "tlsfp=info",
            1 => "tlsfp=debug",
            _ => "tlsfp=trace",
        };
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }

    pub fn run(self) -> Result<()> {
        match self.command {
            Command::Pcap { path, json } => run_pcap(&path, json),
            Command::Live { interface } => {
                anyhow::bail!("live capture on {interface} is not wired up yet")
            }
            Command::Serve { bind } => {
                anyhow::bail!("dashboard on {bind} is not wired up yet")
            }
        }
    }
}

/// Fingerprints a capture file and prints one event per line on stdout.
///
/// The summary goes to the log rather than stdout so that piping the output
/// into a tool sees only events, while a human still learns how much of the
/// capture was readable and whether the file was cut short mid packet.
fn run_pcap(path: &std::path::Path, json: bool) -> Result<()> {
    let mut source = PcapFileSource::open(path)
        .with_context(|| format!("cannot open capture {}", path.display()))?;
    let mut pipeline = Pipeline::new(PipelineConfig::default());

    let stdout = std::io::stdout().lock();
    let mut out = std::io::BufWriter::new(stdout);
    let mut write_failure = None;
    pipeline.run(&mut source, |event| {
        use std::io::Write as _;
        let result = if json {
            serde_json::to_writer(&mut out, &event)
                .map_err(anyhow::Error::from)
                .and_then(|()| writeln!(out).map_err(anyhow::Error::from))
        } else {
            writeln!(out, "{event}").map_err(anyhow::Error::from)
        };
        if write_failure.is_none() {
            if let Err(error) = result {
                write_failure = Some(error);
            }
        }
    })?;
    if let Some(error) = write_failure {
        return Err(error.context("writing events to stdout"));
    }
    {
        use std::io::Write as _;
        out.flush().context("flushing events to stdout")?;
    }

    let counters = pipeline.counters();
    tracing::info!(
        frames = counters.frames,
        tcp_segments = counters.tcp_segments,
        events = counters.events,
        flows = counters.flows_created,
        unfinished_tls_streams = counters.unfinished_tls_streams,
        segments_dropped = counters.segments_dropped,
        "capture processed"
    );
    if source.truncated() {
        tracing::warn!("capture file ended mid packet; the tail was not read");
    }
    Ok(())
}
