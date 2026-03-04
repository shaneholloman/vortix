# Roadmap

This document outlines the planned features and direction for Vortix. Priorities may shift based on community feedback and contributions.

## Current Status: v0.1.4 (Beta)

Vortix is currently in **beta**. Core functionality is stable and actively used on macOS. The v0.2.0 release focuses on code health, reliability, and hardening before adding new user-facing features in v0.3.0.

---

## v0.2.0 — "Rock Solid" (Code Health & Reliability)

### Refactoring
- [x] Refactor monolithic `app.rs` (4,000+ lines) into modular `app/` directory
- [x] Integration test suite covering connection state machine, kill switch, profile import, message routing

### Stability & Resilience
- [x] Connection retry with exponential backoff (configurable via `config.toml`)
- [x] Network change detection (gateway monitoring) with auto-reconnect
- [x] Fix `wg-quick --version` hang on macOS (use `which`-based dependency checks)
- [x] Fix kill switch activation on VPN drop (state ordering bug)
- [ ] Improved error messages and recovery
- [ ] Better handling of edge-case VPN disconnections

### Linux Support
- [ ] Ubuntu/Debian support
- [ ] Fedora/RHEL support
- [ ] Arch Linux support
- [ ] Replace macOS-specific commands (`ifconfig`, `netstat`) with cross-platform alternatives

---

## v0.3.0 — "Power User" (UX & Features)

### Profile Management
- [ ] Profile groups with collapsible sidebar sections and `g` key assignment
- [ ] Quick connect to last used profile (`0` keybinding)
- [ ] Connection history overlay (`H` key) with scrollable past sessions

### Shell Integration
- [ ] Shell completions for bash, zsh, fish via `clap_complete`
- [ ] New `vortix completions` subcommand

### Advanced Features
- [ ] Per-profile DNS settings
- [ ] Auto-connect on startup (daemon mode)

---

## Long Term (v1.0+)

### Multi-Protocol Support
- [ ] IKEv2/IPSec support
- [ ] SOCKS5 proxy integration

### Platform Expansion
- [ ] Windows support
- [ ] FreeBSD support

### Integration
- [ ] Homebrew formula
- [ ] AUR package
- [ ] Debian/RPM packages

### Enterprise Features
- [ ] Config file encryption at rest
- [ ] Audit logging
- [ ] Centralized config management

### Performance
- [ ] Reduced memory footprint
- [ ] Lazy loading of profiles
- [ ] Async DNS resolution

---

## 🤝 How to Contribute

1. **Vote on features** — React with 👍 on [Feature Requests](https://github.com/Harry-kp/vortix/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement)
2. **Propose ideas** — Start a thread in [GitHub Discussions](https://github.com/Harry-kp/vortix/discussions)
3. **Submit PRs** — See [CONTRIBUTING.md](CONTRIBUTING.md)

## Versioning Policy

Vortix follows [Semantic Versioning](https://semver.org/):
- **PATCH** (0.1.x): Bug fixes, no breaking changes
- **MINOR** (0.x.0): New features, backward compatible
- **MAJOR** (x.0.0): Breaking changes (with migration guide)

Breaking changes will be documented in [CHANGELOG.md](CHANGELOG.md) with migration instructions.

