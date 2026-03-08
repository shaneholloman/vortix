# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.6] - 2026-03-08

### Bug Fixes

- **ci:** Resolve Clippy and test failures on CI
- Address Copilot review feedback (8 items)
- Spurious "VPN dropped" auto-reconnect on force-kill
- Add scrolling to help overlay
- Isolate tests from real config dir + block mouse passthrough on overlays
- P0 critical fixes — config viewer I/O, min terminal size, search/rename cursor
- Address Copilot review on PR #89
- Address Copilot review on PR #91
- Address Copilot review on PR #92
- Address Copilot review on PR #93
- Resolve all 6 P0 critical issues (#95, #96, #97, #98, #99, #100)
- Address Copilot review on PR #121
- P1 UX improvements and test safety (#104, #103, #102, #115)
- Enable mouse scroll in config viewer overlay
- Address Copilot review on PR #125
- Remove throughput chart empty state
- Restore original chart arrows and disconnected indicator
- Restore header connected indicator and sidebar numbering
- Hardening round 2 — import UX, security, input routing, quit guard
- Address Copilot review comments on PR #140
- Address second round of Copilot review comments
- Verify WireGuard handshake before declaring Connected ([#31](https://github.com/Harry-kp/vortix/pull/31))
- Remove scanner handshake guard causing reconnect loops
- Address Copilot review — auth mask chars, chart x-bound constant
- Enable 6 previously-ignored auth tests to run without root
- Sync action menus with actual panel capabilities
- Address Copilot review — log filter consistency, comment wording

### Features

- V0.2.0 + v0.3.0 — refactor, reliability, and UX overhaul
- P1 group A — duration format, throughput labels, connected badge, stale data
- P1 group B — accessibility, panel shortcuts, context footer, log filtering
- P2 group A — protocol in cockpit, DNS detail, expanded protocol badge
- P2 group B — confirm switch dialog, syntax highlight & scan timestamp already done
- P3 nice-to-have — profile sorting, latency thresholds
- Extracted duplicate function calls, quality threshold exists in one place

### Refactor

- Extract shared confirm dialog component
- Split dashboard.rs into per-panel modules ([#114](https://github.com/Harry-kp/vortix/pull/114))
- Adopt tempfile crate for panic-safe test cleanup ([#116](https://github.com/Harry-kp/vortix/pull/116))

### Testing

- Add coverage for review comment fixes

### Ci

- Pin Rust 1.91.0 in CI and fix remaining lint issues

### Revert

- Remove WireGuard handshake polling that broke connections

### Ui

- Move toast notification from bottom-right to top-right



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

[Unreleased]: https://github.com/Harry-kp/vortix/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Harry-kp/vortix/releases/tag/v0.1.0
