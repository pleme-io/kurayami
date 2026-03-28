//! CLI for the kurayami privacy DNS resolver.

use std::net::SocketAddr;

use std::sync::Arc;

use clap::{Parser, Subcommand, ValueEnum};
use kurayami_core::QueryType;
use kurayami_resolver::{BlocklistFilter, DnsProxy, DohBackend, SystemBackend, TorDnsBackend};

#[derive(Parser)]
#[command(name = "kurayami", version, about = "Privacy DNS resolver with Tor/DoH/DoT backends")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Which DNS backend to use.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum BackendChoice {
    /// OS resolver via `tokio::net::lookup_host`.
    System,
    /// DNS-over-HTTPS (Cloudflare JSON API).
    Doh,
    /// Resolve through the Tor network.
    Tor,
}

#[derive(Subcommand)]
enum Command {
    /// Start the DNS proxy on a local port.
    Start {
        /// Address to listen on.
        #[arg(short, long, default_value = "127.0.0.1:5353")]
        listen: SocketAddr,

        /// DNS backend to use (system, doh).
        #[arg(short, long, default_value = "system")]
        backend: String,

        /// Domains to block (comma-separated).
        #[arg(long)]
        blocklist: Option<String>,
    },

    /// Show proxy status.
    Status,

    /// Flush the DNS cache.
    Flush,

    /// Resolve a domain through the configured backend.
    Test {
        /// Domain name to resolve.
        domain: String,

        /// Record type (A, AAAA, CNAME, MX, TXT).
        #[arg(short = 't', long, default_value = "A")]
        query_type: String,

        /// DNS backend to use for the test query.
        #[arg(short, long, value_enum, default_value_t = BackendChoice::System)]
        backend: BackendChoice,
    },
}

fn parse_query_type(s: &str) -> kurayami_core::Result<QueryType> {
    match s.to_uppercase().as_str() {
        "A" => Ok(QueryType::A),
        "AAAA" => Ok(QueryType::AAAA),
        "CNAME" => Ok(QueryType::CNAME),
        "MX" => Ok(QueryType::MX),
        "TXT" => Ok(QueryType::TXT),
        "SRV" => Ok(QueryType::SRV),
        "PTR" => Ok(QueryType::PTR),
        "NS" => Ok(QueryType::NS),
        "SOA" => Ok(QueryType::SOA),
        "ANY" => Ok(QueryType::ANY),
        other => Err(kurayami_core::Error::InvalidQuery(format!(
            "unknown query type: {other}"
        ))),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Start {
            listen,
            backend,
            blocklist,
        } => {
            let dns_backend: Box<dyn kurayami_core::DnsBackend> = match backend.as_str() {
                "system" => Box::new(SystemBackend::new()),
                "doh" => Box::new(DohBackend::default()),
                other => {
                    eprintln!("unknown backend: {other}");
                    std::process::exit(1);
                }
            };

            let mut proxy = DnsProxy::new(listen, dns_backend);

            if let Some(domains) = blocklist {
                let list: Vec<&str> = domains.split(',').map(str::trim).collect();
                proxy.add_filter(Box::new(BlocklistFilter::new(list)));
            }

            tracing::info!("starting kurayami DNS proxy");
            proxy.run().await?;
        }

        Command::Status => {
            println!("kurayami: no running proxy detected (daemon mode not yet implemented)");
        }

        Command::Flush => {
            println!("kurayami: cache flush not yet implemented");
        }

        Command::Test {
            domain,
            query_type,
            backend,
        } => {
            let qt = parse_query_type(&query_type)?;
            let dns_backend: Box<dyn kurayami_core::DnsBackend> = match backend {
                BackendChoice::System => Box::new(SystemBackend::new()),
                BackendChoice::Doh => Box::new(DohBackend::default()),
                BackendChoice::Tor => {
                    tracing::info!("bootstrapping Tor transport (this may take 10-30s)...");
                    let transport = kakuremino::TorTransport::bootstrap()
                        .await
                        .map_err(|e| anyhow::anyhow!("Tor bootstrap failed: {e}"))?;
                    Box::new(TorDnsBackend::new(Arc::new(transport)))
                }
            };

            let query = kurayami_core::DnsQuery {
                name: domain.clone(),
                query_type: qt,
                source_addr: None,
            };

            match dns_backend.resolve(&query).await {
                Ok(response) => {
                    println!("query: {domain} ({query_type}) via {}", dns_backend.name());
                    println!("answers: {}", response.answers.len());
                    for record in &response.answers {
                        println!(
                            "  {} {:?} TTL={} {:?}",
                            record.name, record.record_type, record.ttl, record.data
                        );
                    }
                }
                Err(e) => {
                    eprintln!("resolve error: {e}");
                    std::process::exit(1);
                }
            }
        }
    }

    Ok(())
}
