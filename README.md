# fogate-wifi

Manage FortiGate WiFi SSID passwords and read-only diagnostics over SSH,
for people who would rather not learn the CLI. A GUI for the day-to-day
stuff, a CLI for the terminal crowd, and a static dashboard for at-a-glance
monitoring.

Built for **FortiGate 7.x** (tested against FortiOS 7.4.1), but tracks the
FortiGate CLI so it works across the line.

## What it does

| Action | GUI button / CLI flag | Device command |
|---|---|---|
| List SSIDs | — / `--list` | `show wireless-controller vap` |
| Rotate one SSID's password | — / `--change <vap>` | `config wireless-controller vap … end` |
| Rotate all SSIDs | — / `--all` | batched config |
| View online WiFi users | 在线 WiFi 用户 | `diagnose wireless-controller wlac -d sta` |
| View AP up/down status | AP 状态 | `get wireless-controller wtp-status` |

The two diagnostics are saved as readable **Markdown** files next to the
executable (a Markdown table of the connected clients, and an online/offline
AP report). The raw device output is never required — it's formatted for a
human.

## 2FA

Login works with or without two-factor authentication. When the device
prompts for an email / SMS / FortiToken code, the GUI pops a small field
and the CLI prompts in the terminal; you type the code once and the command
runs in the same live session. Devices without 2FA just log in directly —
zero overhead. This is the "auto-detect + human-in-the-loop" model: nothing
is automated past the code, so you always know exactly what the device is
about to do.

## Components

- **`fogate-wifi-gui`** — eframe desktop app. Fill in host / port /
  user / password, pick an action, watch a live transcript, get a
  Markdown snapshot. Connection settings persist locally
  (`%LOCALAPPDATA%\fogate-wifi\`), never in source.
- **`fogate-wifi`** (CLI) — the same operations from a terminal:

  ```
  # list SSIDs
  fogate-wifi 10.0.0.1 -u admin --list

  # rotate one
  fogate-wifi 10.0.0.1 -u admin --change "MySSID" --new "S3cr3t!"

  # run any read-only command (diagnostics)
  fogate-wifi 10.0.0.1 -u readonly --run "get wireless-controller wtp-status"
  ```

  Omitting the password prompts for it. The CLI is aimed at read-only
  accounts for diagnostics; password rotation uses admin.
- **`otp-probe`** — a dev helper that auto-feeds a fresh OTP code read from
  a local inbox file, for testing 2FA flows headlessly. Not part of the
  day-to-day tooling.
- **`dashboard/index.html`** — a single-file static dashboard mock-up
  (WiFi users + AP status, 5-minute auto-refresh layout). Open it in a
  browser; it ships sample data. The live-data backend is on the roadmap.

## Build

Windows, MSVC toolchain. From a developer PowerShell:

```powershell
cargo build --release --bin fogate-wifi-gui --bin fogate-wifi
```

Prerequisites: Rust + the MSVC linker (`vcvars64`). The repo does not
vendor a linker config because the absolute path is machine-specific;
point the MSVC linker in your environment and build.

Run tests (the snapshot formatters are pinned to real device captures):

```powershell
cargo test --lib
```

## Security notes

- No plaintext credentials are baked into the repo. The GUI's saved
  connection file is on the user's own machine only.
- Everything is read-only except explicit password rotation, which is a
  deliberate, single-account action.

## Roadmap

- Live dashboard backend (auto-pull over the CLI every 5 min, JSON).
- CSV export alongside Markdown.
