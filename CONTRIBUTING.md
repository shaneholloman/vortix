# Contributing to Vortix

Thanks for your interest in contributing! 🎉

## Quick Start

```bash
git clone https://github.com/Harry-kp/vortix.git
cd vortix
cargo build
sudo cargo run
```

## Ways to Contribute

- 🐛 **Report bugs** — Open an issue with steps to reproduce
- 💡 **Suggest features** — Check the [roadmap](ROADMAP.md) first, then open an issue
- 📖 **Improve docs** — README, code comments, examples
- 🧪 **Add tests** — Unit tests, integration tests
- 🍎 **Linux support** — Help port macOS-specific code

## Linux Help Wanted

Vortix is developed primarily on macOS, so Linux users can have outsized impact.

Ways Linux contributors can help:
- Test PRs and release candidates on Ubuntu, Fedora, and Arch
- Report distro-specific issues around firewall backends, DNS detection, and privilege handling
- Contribute fixes for Linux-only regressions
- Share packaging and install feedback from real systems

If you regularly use Vortix on Linux and want to help more deeply, start in the [Linux tester discussion](https://github.com/Harry-kp/vortix/discussions/184) with your distro and what you are willing to test.

## Development Workflow

1. Fork the repo
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Make your changes
4. Run checks:
   ```bash
   cargo fmt        # Format code
   cargo clippy     # Lint
   cargo test       # Run tests
   ```
5. Commit with [conventional commits](https://www.conventionalcommits.org/):
   - `feat:` new feature
   - `fix:` bug fix
   - `docs:` documentation
   - `refactor:` code refactoring
6. Push and open a PR

## Code Style

- Run `cargo fmt` before committing
- Run `cargo clippy` and fix all warnings
- Keep functions small and focused
- Add doc comments for public APIs

## Testing

Vortix requires root for VPN operations. For testing:

```bash
# Run unit tests (no root needed)
cargo test

# Run with demo mode (masks sensitive data)
sudo cargo run -- --demo
```

For Linux bug reports, include as much of the following as possible:
- distro + version
- kernel version
- install method (`cargo`, Homebrew, npm, package manager, binary installer)
- `vortix report`
- whether your system uses `iptables`, `nftables`, `firewalld`, `NetworkManager`, or `systemd-resolved`

## Questions?

Open a [discussion](https://github.com/Harry-kp/vortix/discussions) or reach out on [Twitter/X](https://twitter.com/harrykp007).
