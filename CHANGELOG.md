# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.6] - 2026-03-08

### Bug Fixes

- Fix `pkill openvpn` killing all system OpenVPN processes instead of only Vortix-managed ones ([#95](https://github.com/Harry-kp/vortix/issues/95))
- Fix kill switch state file written to world-readable `/tmp/` ([#96](https://github.com/Harry-kp/vortix/issues/96))
- Fix kill switch displaying "Blocking" without root, giving a false sense of security ([#97](https://github.com/Harry-kp/vortix/issues/97))
- Fix Unicode text input causing panic in text field handlers ([#98](https://github.com/Harry-kp/vortix/issues/98))
- Add `Drop` impl on `App` to clean up kill switch rules and VPN processes on panic ([#99](https://github.com/Harry-kp/vortix/issues/99))
- Fix disconnect failure leaving app in "Disconnected" state while VPN process may still be running ([#100](https://github.com/Harry-kp/vortix/issues/100))
- Fix spurious "VPN dropped" auto-reconnect triggered by force-kill
- Fix config viewer overlay not loading file contents on open
- Fix minimum terminal size check causing blank screen on small terminals
- Fix search and rename cursor position on multi-byte UTF-8 input
- Fix mouse events passing through overlays to background panels
- Fix help overlay not being scrollable
- Fix ISP and location text truncated too aggressively on narrow terminals ([#104](https://github.com/Harry-kp/vortix/issues/104))
- Fix connection details panel mostly empty when disconnected ([#102](https://github.com/Harry-kp/vortix/issues/102))
- Fix import overlay closing immediately on URL import or empty directory
- Fix `g`/`G`/Home/End keys not routing correctly when logs panel is focused
- Fix mouse scroll not working on hovered panel (only worked on focused panel)
- Fix profile names overflowing sidebar column when names are long
- Fix password mask using byte count instead of character count for multi-byte input
- Enable config viewer overlay to be scrollable with mouse
- Fix action menus not listing all available panel actions (Sort, Rename, Filter, Kill Switch)

### Features

- Add human-readable connection duration format (e.g., "2h 15m" instead of seconds)
- Add throughput chart with upload/download speed labels and color legend ([#103](https://github.com/Harry-kp/vortix/issues/103))
- Add active connection badge (checkmark) next to connected profile in sidebar
- Clear stale telemetry data on disconnect to avoid showing previous session info
- Add keyboard accessibility for all panels with Tab/Shift+Tab cycling
- Add panel-specific keyboard shortcuts displayed in context footer
- Add log level filtering (Error/Warn/Info) with `f` key
- Show protocol tag (WG/OVPN) in cockpit header bar when connected
- Show DNS server provider name (Cloudflare, Google, Quad9) in security panel
- Add confirmation dialog when switching profiles while connected
- Add confirmation dialog when quitting with an active VPN connection
- Add profile sorting (name, protocol, last used) with `s` key
- Add connection quality thresholds (Poor/Fair/Excellent) based on latency, jitter, and packet loss
- Move toast notifications from bottom-right to top-right for better visibility

### Refactor

- Split 2081-line `dashboard.rs` into 13 focused per-panel modules ([#114](https://github.com/Harry-kp/vortix/issues/114))
- Extract shared confirmation dialog component to reduce code duplication
- Adopt `tempfile` crate for panic-safe test cleanup across all 31 test sites ([#116](https://github.com/Harry-kp/vortix/issues/116))
- Sanitize profile names with strict ASCII-only validation for process management
- Consolidate confirmation dialog input handling into shared `handle_confirm_keys`
- Route inline key handlers (rename, search, help, log filter) through Message dispatch for TEA consistency

### Testing

- Enable 6 previously-ignored auth tests to run without root privileges
- Add 19 new tests covering confirm dialog keys, Home/End panel awareness, profile name sanitization, truncation edge cases, and import overlay behavior
- Migrate all test temp file creation to `tempfile` crate for automatic cleanup on panic

### CI

- Pin Rust 1.91.0 in CI and fix remaining lint issues



## [0.1.5] - 2026-02-16

### Bug Fixes

- Address PR review feedback for bug report feature

### Documentation

- Add roadmap and feature voting links to README
- Add vortix report and Nix installation to README
- Rearrange badges, add Nix flake and npm downloads badges

### Features

- Add `vortix report` bug report command

### Miscellaneous

- **deps:** Bump the rust-minor group with 2 updates ([#40](https://github.com/Harry-kp/vortix/pull/40))



## [0.1.4] - 2026-02-12

### Documentation

- Add sudo PATH troubleshooting for cargo install on Linux
- Restructure README for clarity and fix misleading info
- Move sudo PATH fix to prominent section after installation

### Features

- Add Homebrew and npm package manager support



## [0.1.3] - 2026-02-11

### Bug Fixes

- Prevent TUI freeze when no network connection is available
- **ci:** Gate macOS-only symbols behind cfg to resolve Linux dead_code errors
- Prevent UTF-8 panic when truncating log messages in TUI

### Documentation

- **readme:** Add installation for arch linux ([#27](https://github.com/Harry-kp/vortix/pull/27))
- Add directory structure and configuration guide to README
- Clarify file ownership and permissions in README
- Update configuration reference with all configurable settings

### Features

- Configurable config directory with settings, migration, and sudo ownership
- Harden VPN lifecycle, structured logging, and configurable settings
- Startup dependency check with toast warning for missing tools



## [0.1.2] - 2026-02-07

### Bug Fixes

- Resolve clippy errors on Linux CI (Rust 1.93)

### Documentation

- Add star history graph to README
- Add ROADMAP and GitHub Sponsors funding
- Add downloads and stars badges to README
- Add Terminal Trove feature mention
- Fix roadmap links to point to feature requests
- Add comparison table, CONTRIBUTING.md, and issue/PR templates
- Add macOS, Rust, Sponsors, and PRs Welcome badges

### Features

- Add Linux platform support with cross-platform abstraction layer
- Robust VPN state machine and strict config import validation
- OpenVPN credential management and UX improvements

### Miscellaneous

- **deps:** Bump clap from 4.5.54 to 4.5.56 in the rust-minor group ([#23](https://github.com/Harry-kp/vortix/pull/23))



## [0.1.1] - 2026-01-14

### Bug Fixes

- Address Clippy and Copilot review comments

### Miscellaneous

- **deps:** Bump nix from 0.29.0 to 0.30.1 ([#7](https://github.com/Harry-kp/vortix/pull/7))
- **deps:** Bump libc from 0.2.179 to 0.2.180 in the rust-minor group ([#9](https://github.com/Harry-kp/vortix/pull/9))

### Refactor

- Centralized logging, optimized deps, improved UI



## [0.1.0] - 2026-01-02

### Added
- Initial release of Vortix VPN Manager
- TUI dashboard with real-time network telemetry
- WireGuard profile support (.conf files)
- OpenVPN profile support (.ovpn files)
- Quick slots (1-5) for favorite connections
- Profile import via TUI (`i` key) and CLI (`vortix import`)
- Self-update command (`vortix update`)
- IPv6 leak detection
- DNS leak detection
- Insecure protocol detection (HTTP, FTP, Telnet)
- Live throughput monitoring (upload/download speeds)
- Connection uptime tracking
- Nordic Frost color theme
- Keyboard-driven interface with help overlay (`?` key)

### Security
- Config files stored with 600 permissions
- Root privilege requirement for network interface management

[Unreleased]: https://github.com/Harry-kp/vortix/compare/v0.1.6...HEAD
[0.1.6]: https://github.com/Harry-kp/vortix/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/Harry-kp/vortix/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/Harry-kp/vortix/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/Harry-kp/vortix/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/Harry-kp/vortix/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/Harry-kp/vortix/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Harry-kp/vortix/releases/tag/v0.1.0
