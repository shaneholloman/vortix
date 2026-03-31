---
name: Bug Report
about: Report a bug to help us improve Vortix
title: "[Bug] "
labels: bug
assignees: ""
---

## Bug Description
<!-- What happened? What did you expect instead? -->


## Steps to Reproduce
<!--
1. Run `sudo vortix`
2. Select profile '...'
3. See error
-->

1.
2.
3.

## Environment
<!--
Tip: Run `vortix report` to auto-generate this entire section.
Or fill in manually:
-->

```
Vortix:       [version] ([install method])
OS:           [os] ([arch])
Terminal:     [TERM] ([cols x rows])
Shell:        [shell]
Running as:   [user / root]
```

### Linux-specific details (if applicable)

```
Distro:       [Ubuntu / Fedora / Arch / etc]
Kernel:       [kernel version]
Firewall:     [iptables / nftables / firewalld / unknown]
DNS stack:    [systemd-resolved / NetworkManager / resolv.conf / unknown]
Privilege:    [sudo vortix / root shell / other]
```

## Dependencies
<!--
Tip: Run `vortix report` to auto-detect these.
Or list the relevant tools:
-->

```
curl         [path] ([version])
wg-quick     [path]
wg           [path] ([version])
openvpn      [path] ([version])
```

## Config

```
Directory:   [config dir] ([source])
config.toml: [found / not found]
Profiles:    [count] ([wg] WireGuard, [ovpn] OpenVPN)
Kill switch: [state]
```

## Additional Context
<!-- Screenshots, error messages, log snippets (please redact any IPs or server endpoints) -->

If this is a Linux issue, mention whether you can reproduce it consistently and whether it happens on a distro package install or only on a source/binary install.
