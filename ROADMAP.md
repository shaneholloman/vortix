# Roadmap

This document outlines the product direction for Vortix — release by release.

Each release has a **theme**: a single sentence describing what the user gains. Bugs are always fixed within the release they're discovered, but the theme drives what gets prioritized and what new ground is covered.

---

## Current Status: v0.1.6 (Released)

Vortix is a functional TUI VPN manager for macOS with basic Linux support. It has solid internal architecture (TEA message pattern, modular UI, 275+ tests), WireGuard + OpenVPN support, a kill switch, real-time telemetry, and profile management.

**What v0.1.6 delivered:** Massive hardening — 19 bug fixes, 14 features, dashboard split into 13 modules, panic-safe test cleanup, and 6 previously-ignored tests restored.

---

## v0.1.7 — "Trust the Dashboard"

> Every number, label, and state shown on screen is accurate.

**Why this matters:** A VPN manager that shows wrong information is worse than one that shows nothing. Users make security decisions based on what the dashboard says. If it says "EXCELLENT" when there's no data, or floods the log with false warnings, users lose trust.

### Scope

| Issue | Title | Category |
|---|---|---|
| #110 | Exponential backoff can overflow to infinite sleep | State machine |
| #111 | Renaming a profile breaks reconnect | State machine |
| #112 | Deleting a profile during Connecting causes confusion | State machine |
| #113 | IP leak warning fires every tick — floods activity log | Telemetry |
| #132 | 0ms latency falsely shows EXCELLENT quality | Display accuracy |
| #106 | Action menu labels are misleading | Label accuracy |
| #105 | CloseOverlay also un-zooms the panel | UX consistency |

### Definition of Done

- [ ] No state machine operation leaves the app in an unrecoverable state
- [ ] Every metric displayed has a "no data yet" state instead of false values
- [ ] Action menu labels accurately describe what each action does
- [ ] Layout state (zoom) is independent of overlay state
- [ ] All fixes have corresponding unit tests

**Target:** 1 week after v0.1.6

---

## v0.1.8 — "Polished & Consistent"

> The UI feels like one cohesive product, not a collection of features.

**Why this matters:** Vortix has grown fast. Features were added across multiple sprints by different contributors. The result is small inconsistencies — different cursor styles per overlay, hardcoded colors, footer text that breaks on narrow terminals. This release makes the app feel intentionally designed.

### Scope

| Issue | Title | Category |
|---|---|---|
| #109 | Replace hardcoded colors with theme constants | Code quality |
| #135 | Cursor style inconsistent across overlays | Visual consistency |
| #134 | Footer truncates Help and Quit hints first | Responsive layout |
| #107 | Clipboard copy fails silently on Wayland | Linux support |
| #139 | No click-to-select for profiles in sidebar | Mouse support |
| #136 | URL import leaves temp file behind | Cleanup |
| #137 | Add tests for rename_profile path traversal | Test coverage |
| #123 | Generalize centered_rect helper | Code quality |
| #124 | Include latency in QualityLevel classification | Display accuracy |

### Definition of Done

- [ ] All UI colors come from `theme.rs` constants — no raw `Color::Rgb` in panel code
- [ ] All text-input overlays use the same cursor style
- [ ] Footer gracefully degrades on terminals < 80 columns
- [ ] Clipboard works on macOS (pbcopy), X11 (xclip), and Wayland (wl-copy)
- [ ] Mouse click selects a profile in the sidebar
- [ ] No temp file leaks from any import path

**Target:** 2 weeks after v0.1.7

---

## v0.2.0 — "Works Everywhere"

> First-class Linux support. Cross-platform parity.

**Why this matters:** Vortix works on Linux but relies on macOS-specific commands in several places. Half of VPN users are on Linux. This release makes Linux a first-class citizen, not an afterthought.

### Scope

- Replace macOS-specific commands (`ifconfig`, `netstat`) with cross-platform alternatives
- WireGuard handshake verification (#31) with platform-aware `wg show` handling
- Test on Ubuntu, Fedora, and Arch Linux
- Add distro-specific installation instructions
- CI matrix: macOS + Ubuntu + Fedora
- Wayland and X11 clipboard support (started in v0.1.8)

### Definition of Done

- [ ] `cargo test` passes on macOS, Ubuntu 22.04, and Fedora 39
- [ ] No `#[cfg(target_os = "macos")]` code runs on Linux (clean separation)
- [ ] WireGuard handshake check works on both macOS (utun) and Linux (wg0) interface naming
- [ ] Installation works via Homebrew (macOS), cargo install, AUR, and Nix

**Target:** 4 weeks after v0.1.8

---

## v0.3.0 — "Power User"

> Features for people who use Vortix every day.

**Why this matters:** Vortix's core is solid. Now it needs the features that turn casual users into daily drivers — automation, organization, and shell integration.

### Scope

- Profile groups with collapsible sidebar sections
- Lifecycle hooks: pre/post connect/disconnect scripts (#36)
- Auto-connect on startup / daemon mode (#16)
- Shell completions for bash, zsh, fish via `clap_complete`
- Connection history overlay with scrollable past sessions
- Per-profile DNS settings

### Definition of Done

- [ ] Users can organize 20+ profiles without scrolling
- [ ] `vortix` can run headless as a daemon with auto-connect
- [ ] Shell completions install via `vortix completions <shell>`
- [ ] Pre/post hooks execute with connection context environment variables

**Target:** 6 weeks after v0.2.0

---

## v1.0 — "Production Ready"

> Enterprise-grade, multi-protocol, multi-platform.

### Scope

- Split tunneling configuration (#15)
- Windows support (#17)
- IKEv2/IPSec support
- SOCKS5 proxy integration
- Config file encryption at rest
- Audit logging
- Centralized config management
- Debian/RPM packages

---

## Versioning Policy

Vortix follows [Semantic Versioning](https://semver.org/):
- **PATCH** (0.1.x): Bug fixes, UX polish, no breaking changes
- **MINOR** (0.x.0): New features, backward compatible
- **MAJOR** (x.0.0): Breaking changes (with migration guide)

Breaking changes will be documented in [CHANGELOG.md](CHANGELOG.md) with migration instructions.

## How to Contribute

1. **Pick an issue** — Issues tagged [`good first issue`](https://github.com/Harry-kp/vortix/labels/good%20first%20issue) have detailed implementation plans
2. **Vote on features** — React with 👍 on [Feature Requests](https://github.com/Harry-kp/vortix/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement)
3. **Propose ideas** — Start a thread in [GitHub Discussions](https://github.com/Harry-kp/vortix/discussions)
4. **Submit PRs** — See [CONTRIBUTING.md](CONTRIBUTING.md)
