# kurayami

Privacy DNS resolver.

Local DNS proxy that resolves queries through encrypted and anonymous channels --
DNS-over-HTTPS, DNS-over-TLS, DNS-over-QUIC, or Tor. Includes domain blocklist
and regex filtering, response caching, and multiple upstream resolver support.
All traffic stays off plaintext UDP by default.

## Quick Start

```bash
cargo test                   # run all 64 tests
cargo build --release        # release binary
nix build                    # Nix hermetic build
```

## Crates

| Crate | Purpose |
|-------|---------|
| `kurayami-core` | Traits and types: `DnsBackend`, `DnsFilter`, query/response wire types |
| `kurayami-resolver` | Backends (system, DoH) and filters (blocklist, regex, composite) |
| `kurayami-cli` | CLI binary with `start`, `status`, `flush`, and `test` subcommands |

## Backends

| Backend | Status | Protocol |
|---------|--------|----------|
| system | Working | OS resolver |
| doh | Stub | DNS-over-HTTPS |
| dot | Planned | DNS-over-TLS |
| doq | Planned | DNS-over-QUIC |
| tor | Planned | Resolve through Tor circuit |

## Usage

```bash
# Start the local DNS proxy
kurayami start --listen 127.0.0.1:5353 --backend system

# Test a single lookup
kurayami test example.com -t A

# Check resolver status
kurayami status

# Flush the DNS cache
kurayami flush
```

Configuration is managed via shikumi: `~/.config/kurayami/kurayami.yaml`.

## License

MIT
