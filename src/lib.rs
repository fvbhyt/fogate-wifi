//! fogate-wifi: manage FortiGate WiFi SSID passwords over SSH CLI.
//!
//! Public modules:
//! - `ssh`:  raw SSH exec helper (russh)
//! - `core`: transport-agnostic business logic (list / parse / rotate)
//!
//! Two binaries use this crate:
//! - `fogate-wifi`       — CLI
//! - `fogate-wifi-gui`   — egui native window

pub mod core;
pub mod ssh;
pub mod ssh2fa;
