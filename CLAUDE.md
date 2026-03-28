# Kurayami — Privacy DNS Resolver

Local DNS proxy that resolves through Tor, VPN, or encrypted DNS (DoH/DoT/DoQ).

## Architecture

Three-crate workspace:

| Crate | Purpose |
|-------|---------|
| `kurayami-core` | Types and traits: `DnsBackend`, `DnsFilter`, query/response wire types, errors |
| `kurayami-resolver` | Concrete backends (system, DoH) and filters (blocklist, regex, composite) |
| `kurayami-cli` | CLI binary (`kurayami`) with start/status/flush/test subcommands |

## Backends

| Backend | Status | Description |
|---------|--------|-------------|
| `system` | Working | OS resolver via `tokio::net::lookup_host` |
| `doh` | Stub | DNS-over-HTTPS (wireformat POST to upstream) |
| `dot` | Planned | DNS-over-TLS |
| `doq` | Planned | DNS-over-QUIC |
| `tor` | Planned | Resolve through Tor circuit |

## Filters

- **BlocklistFilter** — exact domain match against a HashSet
- **RegexFilter** — regex pattern matching on domain names
- **CompositeFilter** — chains multiple filters (blocks if any child blocks)

## Build

```bash
cargo check                      # type check
cargo test                       # run all tests
cargo build --release            # release build
nix build                        # Nix build via substrate workspace builder
```

## CLI Usage

```bash
kurayami start --listen 127.0.0.1:5353 --backend system
kurayami test example.com -t A
kurayami status
kurayami flush
```

## Config

Uses shikumi for configuration: `~/.config/kurayami/kurayami.yaml`

## Conventions

- Edition 2024, Rust 1.89.0+, MIT license
- Pure Rust (rustls, no native-tls / C FFI)
- clippy pedantic, release profile optimized (LTO, strip, opt-level z)
