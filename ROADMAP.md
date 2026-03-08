# Roadmap

Vortix exists because managing VPN connections from the terminal should feel as natural as `git` or `vim` — fast, keyboard-driven, and transparent about what's happening with your network.

This roadmap describes the journey from "useful CLI tool" to "the VPN manager people recommend to friends."

---

## Where We Are: v0.1.6

A developer installs Vortix, imports a profile, connects. It works. They see real-time telemetry, a kill switch, profile management. But they notice rough edges: the quality indicator says "EXCELLENT" before any data arrives, the activity log fills with duplicate warnings, renaming a profile quietly breaks reconnect. They think: *"This is cool, but can I trust it?"*

That question drives everything that follows.

---

## v0.1.7 — "Dependable"

**The promise:** You can rely on Vortix for your daily VPN without second-guessing what it tells you.

**What changes for the user:**

1. **Connection quality monitoring becomes real.** Today, the quality indicator shows "EXCELLENT" with no data, and doesn't factor in latency at all. After v0.1.7, you see "Measuring..." until real telemetry arrives, and then a meaningful Excellent/Fair/Poor rating based on latency, jitter, and packet loss combined. The number in the dashboard means something.

2. **Reconnect does what you expect.** Today, pressing `r` reconnects to a hidden "last connected" profile — not the one you're looking at in the sidebar. After v0.1.7, reconnect in the sidebar context operates on the selected profile. The label says exactly what happens.

3. **The state machine is bulletproof.** Rename a profile that was previously connected? Reconnect still finds it. Delete a profile while it's connecting? Blocked with a clear message. Retry loop after a failed connection? Capped at 5 minutes, not 12 days.

4. **The activity log is useful again.** Today, "IP unchanged" warnings fire every 30 seconds while connected — 120 lines per hour of noise. After v0.1.7, each warning fires once per session. The log shows things worth reading.

**What this unlocks:** After v0.1.7, a user can connect in the morning, work all day, and trust that Vortix is accurately monitoring their connection. This is the minimum bar for anyone to adopt it as their daily VPN tool.

---

## v0.1.8 — "Feels Like One Product"

**The promise:** Every pixel and interaction feels intentionally designed — not bolted together from different sprints.

**What changes for the user:**

1. **A real theming system.** Today, colors are hardcoded in 13 different UI files. After v0.1.8, every color comes from `theme.rs`. This isn't just code cleanup — it's the foundation for user-selectable themes (Nord, Dracula, Solarized) in a future release. The app looks cohesive because it IS cohesive.

2. **The sidebar becomes a workspace.** Click a profile to select it (not just keyboard). See your profiles organized and navigable. The sidebar stops being a dumb list and starts being a control panel.

3. **It works on every terminal.** Narrow terminal? The footer degrades gracefully — Help and Quit are always visible. Wayland? Clipboard copy works. Small screen? No truncation artifacts. The app respects your environment instead of fighting it.

4. **Consistent interactions everywhere.** Same cursor style in every text field. Same overlay behavior. Same keyboard patterns. A user who learns one overlay has learned them all.

**What this unlocks:** After v0.1.8, Vortix screenshots look good in a README. People share it on Reddit and Hacker News because it *looks* like a tool worth trying. First impressions matter.

---

## v0.2.0 — "Universal"

**The promise:** If you use a terminal, Vortix works on your OS.

**What changes for the user:**

Today, Vortix is a macOS-first tool that happens to compile on Linux. v0.2.0 makes Linux a first-class citizen:

1. **Platform-aware networking.** WireGuard interface detection works on both macOS (`utun3`) and Linux (`wg0`). No more handshake check failures because the OS names interfaces differently. `ifconfig`/`netstat` replaced with cross-platform alternatives.

2. **CI guarantees.** Every commit is tested on macOS, Ubuntu, and Fedora. Platform bugs are caught before release, not by users.

3. **Distro-native installation.** Homebrew (macOS), AUR (Arch), Nix flake, cargo install. One command to install, everywhere.

**What this unlocks:** The addressable market doubles. Linux VPN users — sysadmins, security researchers, privacy advocates — can adopt Vortix. This is where community growth accelerates.

---

## v0.3.0 — "Set and Forget"

**The promise:** Vortix manages your VPN so you don't have to think about it.

**What changes for the user:**

1. **Auto-connect on startup.** Configure a default profile, and Vortix connects the moment you open a terminal (or runs as a background daemon). For remote workers, this means their VPN is always on.

2. **Lifecycle hooks.** Run a script before connecting (check if on trusted network, update firewall rules) or after disconnecting (flush DNS, restart services). Vortix becomes composable with your existing workflow.

3. **Profile groups.** Your 20 profiles organized into collapsible sections: "Work", "Personal", "Testing". With `g` key assignment for instant group switching.

4. **Shell completions.** `vortix <tab>` just works in bash, zsh, and fish.

**What this unlocks:** The "I use it every day" users. The ones who put Vortix in their dotfiles, recommend it in blog posts, and contribute back to the project.

---

## v1.0 — "For Everyone"

**The promise:** Production-grade VPN management for individuals and teams.

- **Split tunneling** — route only specific traffic through the VPN
- **Windows support** — the last platform barrier
- **Multi-protocol** — IKEv2/IPSec alongside WireGuard and OpenVPN
- **Config encryption** — credentials encrypted at rest
- **Audit logging** — who connected where, when
- **Centralized management** — shared config for teams

---

## Release Philosophy

- **Each release earns something.** v0.1.7 earns trust. v0.1.8 earns admiration. v0.2.0 earns reach. v0.3.0 earns loyalty. v1.0 earns revenue.
- **Bugs are table stakes.** Every release fixes bugs, but that's not the headline. The headline is what the user can now DO.
- **Features ship with quality.** No feature lands without tests, without consistent UI, without documentation. A half-shipped feature is worse than no feature.

## How to Contribute

1. **Pick an issue** — Issues tagged [`good first issue`](https://github.com/Harry-kp/vortix/labels/good%20first%20issue) have detailed implementation plans
2. **Vote on features** — React with 👍 on [Feature Requests](https://github.com/Harry-kp/vortix/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement)
3. **Propose ideas** — Start a thread in [GitHub Discussions](https://github.com/Harry-kp/vortix/discussions)
4. **Submit PRs** — See [CONTRIBUTING.md](CONTRIBUTING.md)
