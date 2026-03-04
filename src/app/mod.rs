//! Core application state and logic.
//!
//! This module contains the main [`App`] struct that manages all application state,
//! including VPN connection status, profile management, telemetry data, and UI state.
//!
//! ## Module structure
//! - `input` — Keyboard and mouse event handling
//! - `update` — Message dispatching (TEA-style update function)
//! - `connection` — VPN connection lifecycle management
//! - `profile` — Profile CRUD and import operations
//! - `telemetry_poll` — Background telemetry and scanner polling
//! - `helpers` — Logging, scrolling, toast notifications, and utilities

mod connection;
mod helpers;
mod input;
mod profile;
mod telemetry_poll;
mod update;

#[cfg(test)]
mod tests;

use ratatui::layout::Rect;
use ratatui::widgets::TableState;
use std::collections::HashMap;
use std::sync::mpsc;
use std::time::Instant;

use crate::constants;
use crate::core::scanner;
use crate::core::telemetry::{self, TelemetryUpdate};
use crate::logger;
use crate::message::Message;
use crate::utils;

// Re-export state types for convenient access
pub use crate::state::{
    AuthField, ConnectionState, DetailedConnectionInfo, FocusedPanel, InputMode, Protocol, Toast,
    ToastType, VpnProfile, DISMISS_DURATION,
};

/// Main application state container.
///
/// The `App` struct holds all state for the Vortix TUI application including
/// VPN connection status, loaded profiles, network telemetry, and UI state.
///
/// # Example
///
/// ```ignore
/// let mut app = App::new();
/// app.connect_by_name("my-vpn-profile");
/// ```
#[allow(clippy::struct_excessive_bools)]
pub struct App {
    /// Flag indicating the application should exit.
    pub should_quit: bool,

    // === VPN State ===
    /// Current VPN connection state.
    pub connection_state: ConnectionState,
    /// Loaded VPN profiles.
    pub profiles: Vec<VpnProfile>,
    /// When the current session started.
    pub session_start: Option<Instant>,

    // === Network Telemetry ===
    /// Historical download throughput data points for charting.
    pub down_history: Vec<(f64, f64)>,
    /// Historical upload throughput data points for charting.
    pub up_history: Vec<(f64, f64)>,
    /// Current download rate in bytes/second.
    pub current_down: u64,
    /// Current upload rate in bytes/second.
    pub current_up: u64,
    pub latency_ms: u64,
    pub packet_loss: f32,
    pub jitter_ms: u64,
    pub location: String,
    pub isp: String,
    pub dns_server: String,
    pub ipv6_leak: bool,

    // === System Info ===
    pub public_ip: String,
    /// Real IP captured when disconnected (for comparison when connected)
    pub real_ip: Option<String>,
    /// DNS server captured when disconnected (for leak comparison when connected)
    pub real_dns: Option<String>,
    /// When the last security telemetry update was received.
    pub last_security_check: Option<Instant>,
    /// Name of the last successfully connected profile (for reconnect from Disconnected).
    pub last_connected_profile: Option<String>,
    /// Scroll position for logs panel (logs stored in logger module)
    pub logs_scroll: u16,
    pub logs_auto_scroll: bool,

    // === UI State (Panel-based) ===
    pub focused_panel: FocusedPanel,
    pub zoomed_panel: Option<FocusedPanel>,
    pub input_mode: InputMode,
    pub show_config: bool,
    pub show_action_menu: bool,
    pub show_bulk_menu: bool,
    pub action_menu_state: ratatui::widgets::ListState,
    pub config_scroll: u16,
    pub profile_list_state: TableState,
    pub panel_areas: HashMap<FocusedPanel, Rect>,
    pub toast: Option<Toast>,
    pub terminal_size: (u16, u16),
    pub is_root: bool,
    /// User-configurable application settings.
    pub config: crate::config::AppConfig,
    /// Resolved config directory path.
    pub config_dir: std::path::PathBuf,
    /// Number of connection drops detected this session.
    pub connection_drops: u32,
    /// Profile index queued for auto-connect after current disconnect completes.
    pub pending_connect: Option<usize>,

    // === Kill Switch ===
    /// Kill switch operating mode (Off, Auto, `AlwaysOn`).
    pub killswitch_mode: crate::state::KillSwitchMode,
    /// Current kill switch state (Disabled, Armed, Blocking).
    pub killswitch_state: crate::state::KillSwitchState,

    // === Connection Retry & Auto-Reconnect ===
    /// Current retry attempt number (0 = no retry in progress).
    pub retry_count: u32,
    /// Profile index being retried (set when a retry timer is active).
    pub retry_profile_idx: Option<usize>,
    /// Profile index to auto-reconnect to after an unexpected VPN drop.
    pub auto_reconnect_profile: Option<usize>,

    // === Async Communication ===
    telemetry_rx: Option<mpsc::Receiver<TelemetryUpdate>>,
    /// Send `()` to wake the telemetry worker immediately (e.g. after connect/disconnect).
    telemetry_nudge: Option<mpsc::Sender<()>>,
    pub(crate) cmd_tx: mpsc::Sender<Message>,
    cmd_rx: mpsc::Receiver<Message>,

    // --- Spawn-on-demand background work (no long-running threads) ---
    /// Receiver for the latest scanner result. `Some` = scan in flight or result ready.
    scanner_rx: Option<mpsc::Receiver<Vec<scanner::ActiveSession>>>,
    /// Receiver for network change events (gateway changes).
    netmon_rx: Option<mpsc::Receiver<crate::core::network_monitor::NetworkEvent>>,
    /// Receiver for the latest raw network byte totals. `Some` = fetch in flight.
    netstats_rx: Option<mpsc::Receiver<(u64, u64)>>,
    /// Last total bytes-in reading (for delta calculation).
    last_bytes_in: u64,
    /// Last total bytes-out reading (for delta calculation).
    last_bytes_out: u64,
}

impl App {
    /// Create a new App instance with the given configuration.
    #[allow(clippy::too_many_lines)]
    #[must_use]
    pub fn new(config: crate::config::AppConfig, config_dir: std::path::PathBuf) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel::<Message>();
        let history_size = constants::NETWORK_HISTORY_SIZE;
        #[allow(clippy::cast_precision_loss)]
        let down_history = (0..history_size).map(|i| (i as f64, 0.0)).collect();
        #[allow(clippy::cast_precision_loss)]
        let up_history = (0..history_size).map(|i| (i as f64, 0.0)).collect();
        let mut app = Self {
            should_quit: false,

            connection_state: ConnectionState::Disconnected,
            profiles: Vec::new(),
            session_start: None,

            down_history,
            up_history,
            current_down: 0,
            current_up: 0,
            latency_ms: 0,
            packet_loss: 0.0,
            jitter_ms: 0,
            location: "Detecting...".to_string(),
            isp: "Detecting...".to_string(),
            dns_server: "Detecting...".to_string(),
            ipv6_leak: false,

            public_ip: "Detecting...".to_string(),
            real_ip: None,
            real_dns: None,
            last_security_check: None,
            last_connected_profile: None,
            logs_scroll: 0,
            logs_auto_scroll: true,

            // Panel-based UI state
            focused_panel: FocusedPanel::Sidebar,
            zoomed_panel: None,
            input_mode: InputMode::Normal,
            show_config: false,
            show_action_menu: false,
            show_bulk_menu: false,
            action_menu_state: ratatui::widgets::ListState::default(),
            config_scroll: 0,
            profile_list_state: TableState::default(),
            panel_areas: HashMap::new(),
            toast: None,
            terminal_size: (0, 0),
            is_root: utils::is_root(),
            config,
            config_dir,
            connection_drops: 0,
            pending_connect: None,

            // Kill switch - load from persisted state for crash recovery
            killswitch_mode: crate::state::KillSwitchMode::default(),
            killswitch_state: crate::state::KillSwitchState::default(),

            retry_count: 0,
            retry_profile_idx: None,
            auto_reconnect_profile: None,

            telemetry_rx: None,
            telemetry_nudge: None,
            cmd_tx,
            cmd_rx,
            scanner_rx: None,
            netmon_rx: None,
            netstats_rx: None,
            last_bytes_in: 0,
            last_bytes_out: 0,
        };

        // Recover kill switch state from crash if persisted
        if let Some(persisted) = crate::core::killswitch::load_state() {
            app.killswitch_mode = persisted.mode;
            // If we were blocking when crashed, release it now
            if persisted.state == crate::state::KillSwitchState::Blocking {
                app.log("WARN: Kill switch was blocking when app crashed. Releasing...");
                let _ = crate::core::killswitch::disable_blocking();
                app.killswitch_state = crate::state::KillSwitchState::Disabled;
                crate::core::killswitch::clear_state();
            } else {
                app.killswitch_state = persisted.state;
            }
        }

        // Load profiles from ~/.config/vortix/profiles/
        app.profiles = crate::vpn::load_profiles();

        app.load_metadata();
        app.sort_profiles();

        // Select first profile if available
        if !app.profiles.is_empty() {
            app.profile_list_state.select(Some(0));
        }

        // Apply user's logging preferences
        logger::configure(&app.config.log_level, app.config.max_log_entries);

        // Initialize logs with boot sequence
        app.log(&format!(
            "INIT: {} v{} starting...",
            constants::APP_NAME,
            constants::APP_VERSION
        ));
        app.log(constants::MSG_BACKEND_INIT);

        // Log auto-save location
        {
            let log_path = app.config_dir.join(constants::LOGS_DIR_NAME);
            app.log(&format!("IO: Auto-logging to {}", log_path.display()));
        }

        app.log("SUCCESS: System active. Press [x] for actions.");

        // Check for required system dependencies at startup
        app.check_system_dependencies();

        // Start background telemetry worker
        let telemetry_config = telemetry::TelemetryConfig::from(&app.config);
        let (telem_rx, telem_nudge) = telemetry::spawn_telemetry_worker(telemetry_config);
        app.telemetry_rx = Some(telem_rx);
        app.telemetry_nudge = Some(telem_nudge);

        // Start network change monitor for auto-reconnect
        let netmon_rx = crate::core::network_monitor::spawn_network_monitor(
            std::time::Duration::from_secs(constants::NETWORK_MONITOR_POLL_SECS),
        );
        app.netmon_rx = Some(netmon_rx);

        app.process_external(); // Flush any early messages

        app
    }

    /// Periodic tick from the event loop.
    pub fn on_tick(&mut self) {
        self.handle_message(Message::Tick);
    }

    /// Process all pending external events (telemetry and background commands).
    /// Called by main loop to ensure background feedback appears immediately.
    pub fn process_external(&mut self) {
        // 1. Process Telemetry
        self.process_telemetry();

        // 2. Process Command Feedback
        while let Ok(msg) = self.cmd_rx.try_recv() {
            self.handle_message(msg);
        }
    }

    /// Called when terminal is resized.
    /// In TEA, this dispatches a Resize message.
    pub fn on_resize(&mut self, width: u16, height: u16) {
        self.handle_message(Message::Resize(width, height));
    }

    /// Check if a specific panel should be drawn as focused (visually)
    #[must_use]
    pub fn should_draw_focus(&self, panel: &FocusedPanel) -> bool {
        // If an overlay is active, no background panel has focus
        if self.show_config
            || self.show_action_menu
            || self.show_bulk_menu
            || self.input_mode != InputMode::Normal
        {
            return false;
        }
        // If Zoom is active, ONLY the zoomed panel has focus
        if let Some(zoomed) = &self.zoomed_panel {
            return *zoomed == *panel;
        }
        // Otherwise, standard focus
        self.focused_panel == *panel
    }
}

impl App {
    /// Lightweight constructor for testing: creates channels but spawns no
    /// background threads (telemetry, scanner, network monitor).
    #[must_use]
    pub fn new_test() -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel::<Message>();
        let history_size = constants::NETWORK_HISTORY_SIZE;
        #[allow(clippy::cast_precision_loss)]
        let down_history = (0..history_size).map(|i| (i as f64, 0.0)).collect();
        #[allow(clippy::cast_precision_loss)]
        let up_history = (0..history_size).map(|i| (i as f64, 0.0)).collect();
        Self {
            should_quit: false,
            connection_state: ConnectionState::Disconnected,
            profiles: Vec::new(),
            session_start: None,
            down_history,
            up_history,
            current_down: 0,
            current_up: 0,
            latency_ms: 0,
            packet_loss: 0.0,
            jitter_ms: 0,
            location: String::new(),
            isp: String::new(),
            dns_server: String::new(),
            ipv6_leak: false,
            public_ip: String::new(),
            real_ip: None,
            real_dns: None,
            last_security_check: None,
            last_connected_profile: None,
            logs_scroll: 0,
            logs_auto_scroll: true,
            focused_panel: FocusedPanel::Sidebar,
            zoomed_panel: None,
            input_mode: InputMode::Normal,
            show_config: false,
            show_action_menu: false,
            show_bulk_menu: false,
            action_menu_state: ratatui::widgets::ListState::default(),
            config_scroll: 0,
            profile_list_state: TableState::default(),
            panel_areas: HashMap::new(),
            toast: None,
            terminal_size: (80, 24),
            is_root: false,
            config: crate::config::AppConfig::default(),
            config_dir: std::env::temp_dir().join("vortix_test"),
            connection_drops: 0,
            pending_connect: None,
            killswitch_mode: crate::state::KillSwitchMode::Off,
            killswitch_state: crate::state::KillSwitchState::Disabled,
            retry_count: 0,
            retry_profile_idx: None,
            auto_reconnect_profile: None,
            telemetry_rx: None,
            telemetry_nudge: None,
            cmd_tx,
            cmd_rx,
            scanner_rx: None,
            netmon_rx: None,
            netstats_rx: None,
            last_bytes_in: 0,
            last_bytes_out: 0,
        }
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new(
            crate::config::AppConfig::default(),
            std::env::temp_dir().join("vortix_default"),
        )
    }
}
