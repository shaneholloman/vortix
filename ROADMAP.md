# Roadmap

This document outlines the planned features and direction for Vortix. Priorities may shift based on community feedback and contributions.

## Current Status: v0.1.x (Beta)

Vortix is currently in **beta**. Core functionality is stable and actively used on macOS. Linux support is the next major milestone. Breaking changes are possible until v1.0 but will be documented in the changelog.

---

## 🎯 Near Term (v0.2.x)

### Linux Support
- [ ] Ubuntu/Debian support
- [ ] Fedora/RHEL support
- [ ] Arch Linux support
- [ ] Replace macOS-specific commands (`ifconfig`, `netstat`) with cross-platform alternatives

### Stability & Polish
- [ ] Improved error messages and recovery
- [ ] Better handling of VPN disconnections
- [ ] Connection retry logic with exponential backoff

### UX Improvements
- [ ] Profile groups/folders
- [ ] Quick connect to last used profile
- [ ] Connection history/logs viewer

---

## 🚀 Medium Term (v0.3.x)

### Multi-Protocol Support
- [ ] IKEv2/IPSec support
- [ ] SOCKS5 proxy integration

### Advanced Features
- [ ] Split tunneling configuration
- [ ] Per-profile DNS settings
- [ ] Auto-connect on startup (daemon mode)
- [ ] Network change detection (auto-reconnect)

### Enterprise Features
- [ ] Config file encryption at rest
- [ ] Audit logging
- [ ] Centralized config management

---

## 🌟 Long Term (v1.0+)

### Platform Expansion
- [ ] Windows support
- [ ] FreeBSD support

### Integration
- [ ] Homebrew formula
- [ ] AUR package
- [ ] Debian/RPM packages
- [ ] Shell completions (bash, zsh, fish)

### Performance
- [ ] Reduced memory footprint
- [ ] Lazy loading of profiles
- [ ] Async DNS resolution

---

## 🤝 How to Contribute

1. **Vote on features** — React with 👍 on [GitHub Issues](https://github.com/Harry-kp/vortix/issues)
2. **Discuss ideas** — Use [GitHub Discussions](https://github.com/Harry-kp/vortix/discussions)
3. **Submit PRs** — See [CONTRIBUTING.md](CONTRIBUTING.md)

## Versioning Policy

Vortix follows [Semantic Versioning](https://semver.org/):
- **PATCH** (0.1.x): Bug fixes, no breaking changes
- **MINOR** (0.x.0): New features, backward compatible
- **MAJOR** (x.0.0): Breaking changes (with migration guide)

Breaking changes will be documented in [CHANGELOG.md](CHANGELOG.md) with migration instructions.

