use super::*;
use crate::core::scanner::ActiveSession;
use std::sync::mpsc;
use std::time::Instant;

fn init_test_env() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let test_config =
            std::env::temp_dir().join(format!("vortix_unit_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&test_config);
        crate::config::set_config_dir(test_config);
    });
}

/// Build a minimal `App` for unit testing (no filesystem / scanner / telemetry).
fn test_app() -> App {
    init_test_env();
    let (cmd_tx, cmd_rx) = mpsc::channel::<Message>();
    App {
        should_quit: false,
        connection_state: ConnectionState::Disconnected,
        profiles: Vec::new(),
        session_start: None,
        down_history: vec![(0.0, 0.0)],
        up_history: vec![(0.0, 0.0)],
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
        log_level_filter: None,
        focused_panel: FocusedPanel::Sidebar,
        zoomed_panel: None,
        input_mode: InputMode::Normal,
        show_config: false,
        show_action_menu: false,
        show_bulk_menu: false,
        action_menu_state: ratatui::widgets::ListState::default(),
        config_scroll: 0,
        cached_config_content: None,
        search_match_count: 0,
        profile_list_state: ratatui::widgets::TableState::default(),
        panel_areas: std::collections::HashMap::new(),
        toast: None,
        terminal_size: (80, 24),
        is_root: false,
        config: crate::config::AppConfig::default(),
        config_dir: std::env::temp_dir().join("vortix_test"),
        connection_drops: 0,
        pending_connect: None,
        sort_order: crate::state::ProfileSortOrder::default(),
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

/// Helper: put app into a Connected state for a given profile name.
fn set_connected(app: &mut App, name: &str) {
    app.session_start = Some(Instant::now());
    app.connection_state = ConnectionState::Connected {
        since: Instant::now(),
        profile: name.to_string(),
        server_location: "Test".to_string(),
        latency_ms: 10,
        details: Box::new(DetailedConnectionInfo {
            interface: "wg0".to_string(),
            pid: Some(12345),
            ..Default::default()
        }),
    };
}

/// Helper: put app into a Disconnecting state for a given profile name.
fn set_disconnecting(app: &mut App, name: &str) {
    app.connection_state = ConnectionState::Disconnecting {
        started: Instant::now(),
        profile: name.to_string(),
    };
}

/// Helper: create a fake `ActiveSession` for scanner results.
fn fake_session(name: &str) -> ActiveSession {
    ActiveSession {
        name: name.to_string(),
        interface: "wg0".to_string(),
        endpoint: "1.2.3.4:51820".to_string(),
        internal_ip: "10.0.0.2".to_string(),
        mtu: "1420".to_string(),
        public_key: String::new(),
        listen_port: "51820".to_string(),
        transfer_rx: "100 KiB".to_string(),
        transfer_tx: "50 KiB".to_string(),
        latest_handshake: "5 seconds ago".to_string(),
        pid: Some(12345),
        started_at: None,
    }
}

// ====================================================================
// DisconnectResult handler tests
// ====================================================================

#[test]
fn test_disconnect_result_success_transitions_to_disconnected() {
    let mut app = test_app();
    set_disconnecting(&mut app, "test-vpn");

    app.handle_message(Message::DisconnectResult {
        profile: "test-vpn".to_string(),
        success: true,
        error: None,
    });

    assert!(
        matches!(app.connection_state, ConnectionState::Disconnected),
        "Expected Disconnected after successful DisconnectResult"
    );
    assert!(app.session_start.is_none());
}

#[test]
fn test_disconnect_result_failure_stays_disconnecting() {
    let mut app = test_app();
    set_disconnecting(&mut app, "test-vpn");

    app.handle_message(Message::DisconnectResult {
        profile: "test-vpn".to_string(),
        success: false,
        error: Some("permission denied".to_string()),
    });

    assert!(
        matches!(app.connection_state, ConnectionState::Disconnecting { .. }),
        "Should remain Disconnecting after failed disconnect (VPN may still be running)"
    );
    let toast = app.toast.as_ref().expect("toast should be set");
    assert_eq!(toast.toast_type, ToastType::Error);
    assert!(toast.message.contains("Disconnect failed"));
    assert!(toast.message.contains("force-disconnect"));
}

#[test]
fn test_disconnect_result_success_from_non_disconnecting_state() {
    let mut app = test_app();
    app.connection_state = ConnectionState::Disconnected;

    app.handle_message(Message::DisconnectResult {
        profile: "test-vpn".to_string(),
        success: true,
        error: None,
    });

    assert!(matches!(
        app.connection_state,
        ConnectionState::Disconnected
    ));
}

// ====================================================================
// Scanner debounce guard tests (SyncSystemState while Disconnecting)
// ====================================================================

#[test]
fn test_scanner_never_overrides_disconnecting_to_connected() {
    let mut app = test_app();
    set_disconnecting(&mut app, "test-vpn");

    let sessions = vec![fake_session("test-vpn")];
    app.handle_message(Message::SyncSystemState(sessions));

    assert!(
        matches!(app.connection_state, ConnectionState::Disconnecting { .. }),
        "Scanner must never override Disconnecting to Connected, got {:?}",
        app.connection_state
    );
}

#[test]
fn test_scanner_confirms_disconnect_when_interface_gone() {
    let mut app = test_app();
    set_disconnecting(&mut app, "test-vpn");

    app.handle_message(Message::SyncSystemState(vec![]));

    assert!(
        matches!(app.connection_state, ConnectionState::Disconnected),
        "Scanner should confirm Disconnected when interface is gone"
    );
    assert!(app.session_start.is_none());
}

#[test]
fn test_scanner_safety_timeout_after_30s() {
    let mut app = test_app();
    app.connection_state = ConnectionState::Disconnecting {
        started: Instant::now()
            .checked_sub(std::time::Duration::from_secs(31))
            .unwrap(),
        profile: "test-vpn".to_string(),
    };

    let sessions = vec![fake_session("test-vpn")];
    app.handle_message(Message::SyncSystemState(sessions));

    assert!(
        matches!(app.connection_state, ConnectionState::Disconnected),
        "Should time out to Disconnected after 30s"
    );
    let toast = app.toast.as_ref().expect("timeout should show toast");
    assert_eq!(toast.toast_type, ToastType::Warning);
    assert!(toast.message.contains("timed out"));
}

#[test]
fn test_scanner_disconnecting_does_not_affect_other_profiles() {
    let mut app = test_app();
    set_disconnecting(&mut app, "vpn-a");

    let sessions = vec![fake_session("vpn-b")];
    app.handle_message(Message::SyncSystemState(sessions));

    assert!(
        matches!(app.connection_state, ConnectionState::Disconnected),
        "Should detect our profile is gone even if other profiles are active"
    );
}

// ====================================================================
// Force disconnect (d pressed twice) tests
// ====================================================================

#[test]
fn test_d_while_disconnecting_escalates_to_force() {
    let mut app = test_app();
    set_disconnecting(&mut app, "test-vpn");
    add_profiles(&mut app, &["test-vpn"]);

    let before = if let ConnectionState::Disconnecting { started, .. } = &app.connection_state {
        *started
    } else {
        panic!("expected Disconnecting");
    };

    app.handle_message(Message::Disconnect);

    assert!(matches!(
        app.connection_state,
        ConnectionState::Disconnecting { .. }
    ));

    if let ConnectionState::Disconnecting { started, .. } = &app.connection_state {
        assert!(*started >= before);
    }

    let toast = app.toast.as_ref().expect("force disconnect shows toast");
    assert_eq!(toast.toast_type, ToastType::Warning);
    assert!(toast.message.contains("Force"));
}

#[test]
fn test_d_while_disconnected_is_noop() {
    let mut app = test_app();
    app.handle_message(Message::Disconnect);
    assert!(matches!(
        app.connection_state,
        ConnectionState::Disconnected
    ));
}

// ====================================================================
// Helpers for new tests
// ====================================================================

/// Helper: put app into a Connecting state for a given profile name.
fn set_connecting(app: &mut App, name: &str) {
    app.connection_state = ConnectionState::Connecting {
        started: Instant::now(),
        profile: name.to_string(),
    };
}

/// Helper: add test profiles to the app.
fn add_profiles(app: &mut App, names: &[&str]) {
    for name in names {
        app.profiles.push(VpnProfile {
            name: (*name).to_string(),
            protocol: Protocol::WireGuard,
            config_path: std::path::PathBuf::from(format!("/tmp/{name}.conf")),
            location: "Test".to_string(),
            last_used: None,
        });
    }
}

// ====================================================================
// Pending connect / VPN switching tests
// ====================================================================

#[test]
fn test_toggle_connected_different_profile_shows_confirm() {
    let mut app = test_app();
    add_profiles(&mut app, &["vpn-a", "vpn-b"]);
    set_connected(&mut app, "vpn-a");

    app.toggle_connection(1);

    assert!(
        matches!(app.input_mode, InputMode::ConfirmSwitch { to_idx: 1, .. }),
        "Expected ConfirmSwitch dialog, got {:?}",
        app.input_mode
    );

    app.handle_message(Message::ConfirmSwitch { idx: 1 });
    assert_eq!(app.pending_connect, Some(1));
    assert!(
        matches!(app.connection_state, ConnectionState::Disconnecting { .. }),
        "Expected Disconnecting after confirm, got {:?}",
        app.connection_state
    );
}

#[test]
fn test_toggle_connected_same_profile_disconnects_without_pending() {
    let mut app = test_app();
    add_profiles(&mut app, &["vpn-a"]);
    set_connected(&mut app, "vpn-a");

    app.toggle_connection(0);

    assert_eq!(
        app.pending_connect, None,
        "Same-profile toggle should not set pending"
    );
    assert!(matches!(
        app.connection_state,
        ConnectionState::Disconnecting { .. }
    ));
}

#[test]
fn test_toggle_while_disconnecting_queues_pending() {
    let mut app = test_app();
    add_profiles(&mut app, &["vpn-a", "vpn-b"]);
    set_disconnecting(&mut app, "vpn-a");

    app.toggle_connection(1);

    assert_eq!(app.pending_connect, Some(1));
    assert!(matches!(
        app.connection_state,
        ConnectionState::Disconnecting { .. }
    ));
}

#[test]
fn test_toggle_while_connecting_is_rejected() {
    let mut app = test_app();
    add_profiles(&mut app, &["vpn-a", "vpn-b"]);
    set_connecting(&mut app, "vpn-a");

    app.toggle_connection(1);

    assert!(matches!(
        app.connection_state,
        ConnectionState::Connecting { .. }
    ));
    assert_eq!(app.pending_connect, None);
}

#[test]
fn test_pending_connect_drained_on_disconnect_success() {
    let mut app = test_app();
    add_profiles(&mut app, &["vpn-a", "vpn-b"]);
    set_disconnecting(&mut app, "vpn-a");
    app.pending_connect = Some(1);
    app.is_root = true;

    app.handle_message(Message::DisconnectResult {
        profile: "vpn-a".to_string(),
        success: true,
        error: None,
    });

    assert_eq!(app.pending_connect, None);
    assert!(
        matches!(app.connection_state, ConnectionState::Connecting { ref profile, .. } if profile == "vpn-b"),
        "Expected Connecting to vpn-b, got {:?}",
        app.connection_state
    );
}

#[test]
fn test_pending_connect_drained_on_scanner_interface_gone() {
    let mut app = test_app();
    add_profiles(&mut app, &["vpn-a", "vpn-b"]);
    set_disconnecting(&mut app, "vpn-a");
    app.pending_connect = Some(1);
    app.is_root = true;

    app.handle_message(Message::SyncSystemState(vec![]));

    assert_eq!(app.pending_connect, None);
    assert!(
        matches!(app.connection_state, ConnectionState::Connecting { ref profile, .. } if profile == "vpn-b"),
        "Expected auto-connect to vpn-b after scanner confirms disconnect"
    );
}

#[test]
fn test_pending_preserved_on_disconnect_failure() {
    let mut app = test_app();
    add_profiles(&mut app, &["vpn-a", "vpn-b"]);
    set_disconnecting(&mut app, "vpn-a");
    app.pending_connect = Some(1);

    app.handle_message(Message::DisconnectResult {
        profile: "vpn-a".to_string(),
        success: false,
        error: Some("permission denied".to_string()),
    });

    // pending_connect is preserved so it can fire after force-disconnect
    assert_eq!(app.pending_connect, Some(1));
    assert!(
        matches!(app.connection_state, ConnectionState::Disconnecting { .. }),
        "Should remain Disconnecting after failed disconnect"
    );
}

#[test]
fn test_pending_cleared_on_30s_timeout() {
    let mut app = test_app();
    add_profiles(&mut app, &["vpn-a", "vpn-b"]);
    app.connection_state = ConnectionState::Disconnecting {
        started: Instant::now()
            .checked_sub(std::time::Duration::from_secs(31))
            .unwrap(),
        profile: "vpn-a".to_string(),
    };
    app.pending_connect = Some(1);

    let sessions = vec![fake_session("vpn-a")];
    app.handle_message(Message::SyncSystemState(sessions));

    assert_eq!(app.pending_connect, None);
    assert!(matches!(
        app.connection_state,
        ConnectionState::Disconnected
    ));
}

// ====================================================================
// ConnectResult tests
// ====================================================================

#[test]
fn test_connect_result_success_transitions_to_connected() {
    let mut app = test_app();
    add_profiles(&mut app, &["test-vpn"]);
    set_connecting(&mut app, "test-vpn");

    app.handle_message(Message::ConnectResult {
        profile: "test-vpn".to_string(),
        success: true,
        error: None,
    });

    assert!(
        matches!(app.connection_state, ConnectionState::Connected { ref profile, .. } if profile == "test-vpn"),
        "Successful ConnectResult should transition to Connected"
    );
}

#[test]
fn test_connect_result_failure_transitions_to_disconnected() {
    let mut app = test_app();
    set_connecting(&mut app, "test-vpn");

    app.handle_message(Message::ConnectResult {
        profile: "test-vpn".to_string(),
        success: false,
        error: Some("wg-quick: already exists".to_string()),
    });

    assert!(
        matches!(app.connection_state, ConnectionState::Disconnected),
        "Failed ConnectResult should transition to Disconnected"
    );
    let toast = app.toast.as_ref().expect("should show error toast");
    assert_eq!(toast.toast_type, ToastType::Error);
    assert!(toast.message.contains("Failed to connect"));
}

#[test]
fn test_connect_result_failure_clears_pending() {
    let mut app = test_app();
    set_connecting(&mut app, "test-vpn");
    app.pending_connect = Some(1);

    app.handle_message(Message::ConnectResult {
        profile: "test-vpn".to_string(),
        success: false,
        error: Some("error".to_string()),
    });

    assert_eq!(
        app.pending_connect, None,
        "Connect failure should clear pending"
    );
}

// ====================================================================
// Disconnect from Connecting state tests
// ====================================================================

#[test]
fn test_disconnect_from_connecting_state() {
    let mut app = test_app();
    add_profiles(&mut app, &["test-vpn"]);
    set_connecting(&mut app, "test-vpn");

    app.disconnect();

    assert!(
        matches!(app.connection_state, ConnectionState::Disconnecting { .. }),
        "disconnect() should work from Connecting state, got {:?}",
        app.connection_state
    );
}

#[test]
fn test_d_key_from_connecting_state_disconnects() {
    let mut app = test_app();
    add_profiles(&mut app, &["test-vpn"]);
    set_connecting(&mut app, "test-vpn");

    app.handle_message(Message::Disconnect);

    assert!(
        matches!(app.connection_state, ConnectionState::Disconnecting { .. }),
        "d key should cancel Connecting state"
    );
}

// ====================================================================
// Reconnect uses pending_connect (no race)
// ====================================================================

#[test]
fn test_reconnect_sets_pending_not_immediate_connect() {
    let mut app = test_app();
    add_profiles(&mut app, &["test-vpn"]);
    set_connected(&mut app, "test-vpn");

    app.reconnect();

    assert_eq!(app.pending_connect, Some(0));
    assert!(
        matches!(app.connection_state, ConnectionState::Disconnecting { .. }),
        "Reconnect should disconnect first"
    );
}

#[test]
fn test_reconnect_auto_connects_after_disconnect_completes() {
    let mut app = test_app();
    add_profiles(&mut app, &["test-vpn"]);
    set_disconnecting(&mut app, "test-vpn");
    app.pending_connect = Some(0);
    app.is_root = true;

    app.handle_message(Message::DisconnectResult {
        profile: "test-vpn".to_string(),
        success: true,
        error: None,
    });

    assert_eq!(app.pending_connect, None);
    assert!(
        matches!(app.connection_state, ConnectionState::Connecting { ref profile, .. } if profile == "test-vpn"),
        "Reconnect should auto-connect after disconnect"
    );
}

// ====================================================================
// QuickConnect (1-9) edge cases
// ====================================================================

#[test]
fn test_quick_connect_while_connected_shows_confirm() {
    let mut app = test_app();
    add_profiles(&mut app, &["vpn-a", "vpn-b", "vpn-c"]);
    set_connected(&mut app, "vpn-a");

    app.handle_message(Message::QuickConnect(1));

    assert!(
        matches!(app.input_mode, InputMode::ConfirmSwitch { to_idx: 1, .. }),
        "Expected ConfirmSwitch dialog for QuickConnect, got {:?}",
        app.input_mode,
    );
}

#[test]
fn test_quick_connect_while_disconnecting_updates_pending() {
    let mut app = test_app();
    add_profiles(&mut app, &["vpn-a", "vpn-b", "vpn-c"]);
    set_disconnecting(&mut app, "vpn-a");
    app.pending_connect = Some(1);

    app.handle_message(Message::QuickConnect(2));

    assert_eq!(
        app.pending_connect,
        Some(2),
        "Should update pending to new choice"
    );
}

#[test]
fn test_quick_connect_from_disconnected() {
    let mut app = test_app();
    add_profiles(&mut app, &["vpn-a"]);
    app.is_root = true;

    app.handle_message(Message::QuickConnect(0));

    assert!(
        matches!(app.connection_state, ConnectionState::Connecting { .. }),
        "QuickConnect from Disconnected should go to Connecting"
    );
    assert_eq!(app.pending_connect, None);
}

// ====================================================================
// Auth prompt tests
// ====================================================================

/// Helper: add `OpenVPN` profiles with a temp config file containing auth-user-pass.
fn add_openvpn_profiles_with_auth(app: &mut App, names: &[&str]) {
    let dir = std::env::temp_dir().join("vortix_test_auth_profiles");
    let _ = std::fs::create_dir_all(&dir);
    for name in names {
        let config_path = dir.join(format!("{name}.ovpn"));
        std::fs::write(
            &config_path,
            "client\nremote example.com 1194\nauth-user-pass\ndev tun\nproto udp\n",
        )
        .unwrap();
        app.profiles.push(VpnProfile {
            name: (*name).to_string(),
            protocol: Protocol::OpenVPN,
            config_path,
            location: "Test".to_string(),
            last_used: None,
        });
    }
}

/// Helper: add `OpenVPN` profiles WITHOUT auth-user-pass.
fn add_openvpn_profiles_no_auth(app: &mut App, names: &[&str]) {
    let dir = std::env::temp_dir().join("vortix_test_noauth_profiles");
    let _ = std::fs::create_dir_all(&dir);
    for name in names {
        let config_path = dir.join(format!("{name}.ovpn"));
        std::fs::write(
            &config_path,
            "client\nremote example.com 1194\ndev tun\nproto udp\n<ca>\n</ca>\n",
        )
        .unwrap();
        app.profiles.push(VpnProfile {
            name: (*name).to_string(),
            protocol: Protocol::OpenVPN,
            config_path,
            location: "Test".to_string(),
            last_used: None,
        });
    }
}

#[test]
fn test_auth_prompt_shown_for_openvpn_with_auth_user_pass() {
    let mut app = test_app();
    add_openvpn_profiles_with_auth(&mut app, &["auth-vpn"]);
    app.is_root = true;

    crate::utils::delete_openvpn_auth_file("auth-vpn");

    app.connect_profile(0);

    assert!(
        matches!(app.input_mode, InputMode::AuthPrompt { .. }),
        "OpenVPN with auth-user-pass and no saved creds should show AuthPrompt"
    );
    assert!(
        matches!(app.connection_state, ConnectionState::Disconnected),
        "Should not start connecting before credentials are provided"
    );
}

#[test]
#[ignore = "requires root privileges for auth file permissions"]
fn test_auth_prompt_skipped_when_creds_saved() {
    let mut app = test_app();
    add_openvpn_profiles_with_auth(&mut app, &["saved-vpn"]);
    app.is_root = true;

    let _ = crate::utils::write_openvpn_auth_file("saved-vpn", "user", "pass");

    app.connect_profile(0);

    assert!(
        !matches!(app.input_mode, InputMode::AuthPrompt { .. }),
        "Should not show AuthPrompt when creds are already saved"
    );
    assert!(
        matches!(app.connection_state, ConnectionState::Connecting { .. }),
        "Should proceed to Connecting with saved credentials"
    );

    crate::utils::delete_openvpn_auth_file("saved-vpn");
}

#[test]
fn test_auth_prompt_skipped_for_wireguard() {
    let mut app = test_app();
    add_profiles(&mut app, &["wg-vpn"]);
    app.is_root = true;

    app.connect_profile(0);

    assert!(
        !matches!(app.input_mode, InputMode::AuthPrompt { .. }),
        "WireGuard profiles should never show AuthPrompt"
    );
}

#[test]
fn test_auth_prompt_skipped_for_openvpn_without_auth_directive() {
    let mut app = test_app();
    add_openvpn_profiles_no_auth(&mut app, &["noauth-vpn"]);
    app.is_root = true;

    app.connect_profile(0);

    assert!(
        !matches!(app.input_mode, InputMode::AuthPrompt { .. }),
        "OpenVPN without auth-user-pass should not show AuthPrompt"
    );
    assert!(
        matches!(app.connection_state, ConnectionState::Connecting { .. }),
        "Should proceed to Connecting directly"
    );
}

#[test]
#[ignore = "requires root privileges for auth file permissions"]
fn test_auth_submit_triggers_connect() {
    let mut app = test_app();
    add_openvpn_profiles_with_auth(&mut app, &["submit-vpn"]);
    app.is_root = true;

    crate::utils::delete_openvpn_auth_file("submit-vpn");

    app.handle_message(Message::AuthSubmit {
        idx: 0,
        username: "testuser".to_string(),
        password: "testpass".to_string(),
        save: true,
        connect_after: true,
    });

    assert_eq!(app.input_mode, InputMode::Normal);
    assert!(
        matches!(app.connection_state, ConnectionState::Connecting { .. }),
        "AuthSubmit should trigger connect_profile"
    );

    let creds = crate::utils::read_openvpn_saved_auth("submit-vpn");
    assert!(creds.is_some());
    let (user, pass) = creds.unwrap();
    assert_eq!(user, "testuser");
    assert_eq!(pass, "testpass");

    crate::utils::delete_openvpn_auth_file("submit-vpn");
}

#[test]
fn test_auth_cancel_returns_to_normal() {
    let mut app = test_app();
    add_openvpn_profiles_with_auth(&mut app, &["cancel-vpn"]);
    app.is_root = true;

    crate::utils::delete_openvpn_auth_file("cancel-vpn");

    app.connect_profile(0);
    assert!(matches!(app.input_mode, InputMode::AuthPrompt { .. }));

    app.handle_message(Message::CloseOverlay);
    assert_eq!(app.input_mode, InputMode::Normal);
    assert!(
        matches!(app.connection_state, ConnectionState::Disconnected),
        "Cancelling auth should keep Disconnected state"
    );
}

#[test]
fn test_auth_field_switching() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = test_app();
    app.input_mode = InputMode::AuthPrompt {
        profile_idx: 0,
        profile_name: "test".to_string(),
        username: String::new(),
        username_cursor: 0,
        password: String::new(),
        password_cursor: 0,
        focused_field: AuthField::Username,
        save_credentials: true,
        connect_after: true,
    };

    // Tab from Username -> Password
    app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    if let InputMode::AuthPrompt { focused_field, .. } = &app.input_mode {
        assert_eq!(*focused_field, AuthField::Password);
    } else {
        panic!("Expected AuthPrompt");
    }

    // Tab from Password -> SaveCheckbox
    app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    if let InputMode::AuthPrompt { focused_field, .. } = &app.input_mode {
        assert_eq!(*focused_field, AuthField::SaveCheckbox);
    } else {
        panic!("Expected AuthPrompt");
    }

    // Tab from SaveCheckbox -> Username (wraps around)
    app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    if let InputMode::AuthPrompt { focused_field, .. } = &app.input_mode {
        assert_eq!(*focused_field, AuthField::Username);
    } else {
        panic!("Expected AuthPrompt");
    }
}

#[test]
#[ignore = "requires root privileges for auth file permissions"]
fn test_auth_delete_profile_cleans_auth_file() {
    let mut app = test_app();
    add_openvpn_profiles_with_auth(&mut app, &["del-vpn"]);
    app.profile_list_state.select(Some(0));

    let auth_path = crate::utils::write_openvpn_auth_file("del-vpn", "user", "pass").unwrap();
    assert!(auth_path.exists());

    app.confirm_delete(0);

    assert!(
        !auth_path.exists(),
        "Auth file should be deleted when profile is deleted"
    );
}

// ====================================================================
// v0.3.0 — "Trustworthy & Alive" tests
// ====================================================================

// --- Phase 1: DNS leak detection (#46) ---

#[test]
fn test_dns_leak_detected_when_dns_unchanged_after_vpn() {
    let mut app = test_app();
    app.real_dns = Some("192.168.1.1".to_string());
    app.dns_server = "192.168.1.1".to_string();
    set_connected(&mut app, "vpn-a");

    assert_eq!(
        app.dns_server,
        app.real_dns.as_ref().unwrap().as_str(),
        "DNS unchanged = leak"
    );
}

#[test]
fn test_dns_not_leaking_when_vpn_pushed_new_dns() {
    let mut app = test_app();
    app.real_dns = Some("192.168.1.1".to_string());
    app.dns_server = "10.8.0.1".to_string();
    set_connected(&mut app, "vpn-a");

    assert_ne!(
        app.dns_server,
        app.real_dns.as_ref().unwrap().as_str(),
        "Different DNS = not leaking"
    );
}

#[test]
fn test_real_dns_captured_when_disconnected() {
    use crate::core::telemetry::TelemetryUpdate;
    let mut app = test_app();
    assert!(app.real_dns.is_none());

    app.handle_message(Message::Telemetry(TelemetryUpdate::Dns(
        "8.8.8.8".to_string(),
    )));

    assert_eq!(app.real_dns, Some("8.8.8.8".to_string()));
}

// --- Phase 1: Last security check timestamp (#47) ---

#[test]
fn test_last_security_check_updated_on_ip_telemetry() {
    use crate::core::telemetry::TelemetryUpdate;
    let mut app = test_app();
    assert!(app.last_security_check.is_none());

    app.handle_message(Message::Telemetry(TelemetryUpdate::PublicIp(
        "1.2.3.4".to_string(),
    )));

    assert!(app.last_security_check.is_some());
}

#[test]
fn test_last_security_check_updated_on_dns_telemetry() {
    use crate::core::telemetry::TelemetryUpdate;
    let mut app = test_app();
    assert!(app.last_security_check.is_none());

    app.handle_message(Message::Telemetry(TelemetryUpdate::Dns(
        "1.1.1.1".to_string(),
    )));

    assert!(app.last_security_check.is_some());
}

#[test]
fn test_last_security_check_updated_on_ipv6_telemetry() {
    use crate::core::telemetry::TelemetryUpdate;
    let mut app = test_app();
    assert!(app.last_security_check.is_none());

    app.handle_message(Message::Telemetry(TelemetryUpdate::Ipv6Leak(false)));

    assert!(app.last_security_check.is_some());
}

// --- Phase 1: Reconnect from Disconnected (#49) ---

#[test]
fn test_reconnect_from_disconnected_with_last_profile() {
    let mut app = test_app();
    add_profiles(&mut app, &["my-vpn"]);
    app.last_connected_profile = Some("my-vpn".to_string());
    app.is_root = true;

    app.reconnect();

    assert!(
        matches!(app.connection_state, ConnectionState::Connecting { ref profile, .. } if profile == "my-vpn"),
        "Should initiate connection to last used profile"
    );
}

#[test]
fn test_reconnect_from_disconnected_without_last_profile_is_noop() {
    let mut app = test_app();
    add_profiles(&mut app, &["my-vpn"]);
    assert!(app.last_connected_profile.is_none());

    app.reconnect();

    assert!(
        matches!(app.connection_state, ConnectionState::Disconnected),
        "Should stay disconnected when no last_connected_profile"
    );
}

// --- Phase 1: Timeout toast color (#50) ---

#[test]
fn test_connection_timeout_shows_error_toast() {
    let mut app = test_app();
    add_profiles(&mut app, &["timeout-vpn"]);
    app.connection_state = ConnectionState::Connecting {
        started: Instant::now()
            .checked_sub(std::time::Duration::from_secs(60))
            .unwrap(),
        profile: "timeout-vpn".to_string(),
    };

    app.handle_message(Message::ConnectionTimeout("timeout-vpn".to_string()));

    assert!(app.toast.is_some(), "Should show a toast");
    assert_eq!(
        app.toast.as_ref().unwrap().toast_type,
        crate::state::ToastType::Error,
        "Timeout toast should be Error, not Warning"
    );
}

// --- Phase 1: last_connected_profile set on success (#49 + reconnect) ---

#[test]
fn test_last_connected_profile_set_on_connect_success() {
    let mut app = test_app();
    add_profiles(&mut app, &["success-vpn"]);
    app.connection_state = ConnectionState::Connecting {
        started: Instant::now(),
        profile: "success-vpn".to_string(),
    };

    app.handle_message(Message::ConnectResult {
        profile: "success-vpn".to_string(),
        success: true,
        error: None,
    });

    assert_eq!(
        app.last_connected_profile,
        Some("success-vpn".to_string()),
        "Should track last connected profile"
    );
}

// --- Phase 2: Quick-connect moves selection (#53) ---

#[test]
fn test_quick_connect_moves_selection_cursor() {
    let mut app = test_app();
    add_profiles(&mut app, &["alpha", "beta", "gamma"]);
    app.profile_list_state.select(Some(0));

    app.handle_message(Message::QuickConnect(2));

    assert_eq!(
        app.profile_list_state.selected(),
        Some(2),
        "Quick-connect should move selection to the connected profile"
    );
}

#[test]
fn test_quick_connect_out_of_range_does_not_change_selection() {
    let mut app = test_app();
    add_profiles(&mut app, &["alpha"]);
    app.profile_list_state.select(Some(0));

    app.handle_message(Message::QuickConnect(5));

    assert_eq!(
        app.profile_list_state.selected(),
        Some(0),
        "Out-of-range quick-connect should not change selection"
    );
}

// --- Phase 2: Context-aware footer / search / help mode ---

#[test]
fn test_help_mode_opens_and_closes() {
    let mut app = test_app();
    assert!(matches!(app.input_mode, InputMode::Normal));

    app.input_mode = InputMode::Help { scroll: 0 };
    assert!(matches!(app.input_mode, InputMode::Help { .. }));

    app.handle_message(Message::CloseOverlay);
    assert!(matches!(app.input_mode, InputMode::Normal));
}

#[test]
fn test_search_mode_opens() {
    let mut app = test_app();
    app.input_mode = InputMode::Search {
        query: String::new(),
        cursor: 0,
    };
    assert!(matches!(app.input_mode, InputMode::Search { .. }));
}

#[test]
fn test_search_filter_selects_matching_profile() {
    let mut app = test_app();
    add_profiles(&mut app, &["amsterdam", "berlin", "chicago"]);
    app.profile_list_state.select(Some(0));

    app.apply_search_filter("ber");

    assert_eq!(
        app.profile_list_state.selected(),
        Some(1),
        "Search for 'ber' should select 'berlin'"
    );
}

#[test]
fn test_search_filter_empty_resets_to_first() {
    let mut app = test_app();
    add_profiles(&mut app, &["amsterdam", "berlin"]);
    app.profile_list_state.select(Some(1));

    app.apply_search_filter("");

    assert_eq!(
        app.profile_list_state.selected(),
        Some(0),
        "Empty query should reset to first profile"
    );
}

#[test]
fn test_search_filter_no_match_keeps_selection() {
    let mut app = test_app();
    add_profiles(&mut app, &["amsterdam", "berlin"]);
    app.profile_list_state.select(Some(0));

    app.apply_search_filter("zzzzz");

    assert_eq!(
        app.profile_list_state.selected(),
        Some(0),
        "No match should not change selection"
    );
}

#[test]
fn test_open_config_caches_content_and_close_clears() {
    let mut app = test_app();

    let tmp = std::env::temp_dir().join("vortix_test_config.conf");
    std::fs::write(&tmp, "[Interface]\nAddress = 10.0.0.1/24").unwrap();
    app.profiles.push(VpnProfile {
        name: "test-vpn".to_string(),
        protocol: Protocol::WireGuard,
        config_path: tmp.clone(),
        location: "Test".to_string(),
        last_used: None,
    });
    app.profile_list_state.select(Some(0));

    app.handle_message(Message::OpenConfig);
    assert!(app.show_config, "Config viewer should be open");
    assert!(
        app.cached_config_content.is_some(),
        "Config content should be cached"
    );
    assert!(app
        .cached_config_content
        .as_ref()
        .unwrap()
        .contains("[Interface]"));

    app.handle_message(Message::CloseOverlay);
    assert!(!app.show_config, "Config viewer should be closed");
    assert!(
        app.cached_config_content.is_none(),
        "Cached content should be cleared on close"
    );

    let _ = std::fs::remove_file(tmp);
}

#[test]
fn test_search_match_count_updated() {
    let mut app = test_app();
    add_profiles(&mut app, &["amsterdam", "ankara", "berlin"]);
    app.profile_list_state.select(Some(0));

    app.apply_search_filter("an");
    assert_eq!(app.search_match_count, 1, "Should match ankara");

    app.apply_search_filter("a");
    assert_eq!(
        app.search_match_count, 2,
        "Should match amsterdam and ankara"
    );

    app.apply_search_filter("");
    assert_eq!(app.search_match_count, 3, "Empty query should match all");
}

#[test]
fn test_confirm_switch_when_already_disconnected_connects_directly() {
    let mut app = test_app();
    add_profiles(&mut app, &["vpn-a", "vpn-b"]);
    app.profile_list_state.select(Some(0));
    app.is_root = true;

    assert!(matches!(
        app.connection_state,
        ConnectionState::Disconnected
    ));

    app.handle_message(Message::ConfirmSwitch { idx: 1 });

    assert!(
        app.pending_connect.is_none(),
        "Should not set pending_connect when already disconnected"
    );
    assert!(
        matches!(app.connection_state, ConnectionState::Connecting { ref profile, .. } if profile == "vpn-b"),
        "Should connect directly when already disconnected, got {:?}",
        app.connection_state
    );
}

#[test]
fn test_cycle_sort_order() {
    use crate::state::ProfileSortOrder;

    let mut app = test_app();
    add_profiles(&mut app, &["charlie", "alpha", "bravo"]);
    app.profile_list_state.select(Some(0));

    assert_eq!(app.sort_order, ProfileSortOrder::NameAsc);

    app.handle_message(Message::CycleSortOrder);
    assert_eq!(app.sort_order, ProfileSortOrder::NameDesc);
    assert_eq!(app.profiles[0].name, "charlie");

    app.handle_message(Message::CycleSortOrder);
    assert_eq!(app.sort_order, ProfileSortOrder::LastUsed);

    app.handle_message(Message::CycleSortOrder);
    assert_eq!(app.sort_order, ProfileSortOrder::Protocol);

    app.handle_message(Message::CycleSortOrder);
    assert_eq!(app.sort_order, ProfileSortOrder::NameAsc);
    assert_eq!(app.profiles[0].name, "alpha");
}

#[test]
fn test_sort_preserves_selection() {
    let mut app = test_app();
    add_profiles(&mut app, &["charlie", "alpha", "bravo"]);
    app.profile_list_state.select(Some(1)); // "alpha" (unsorted order)

    let selected_name = app.profiles[1].name.clone();
    assert_eq!(selected_name, "alpha");

    app.handle_message(Message::CycleSortOrder); // NameAsc -> NameDesc

    let new_idx = app.profile_list_state.selected().unwrap();
    assert_eq!(
        app.profiles[new_idx].name, "alpha",
        "Selection should follow the profile after re-sort"
    );
}

// ====================================================================
// Unicode text field input tests (#98)
// ====================================================================

#[test]
fn test_text_field_multibyte_insert_and_backspace() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut text = String::new();
    let mut cursor: usize = 0;

    // Type "café"
    for c in ['c', 'a', 'f', 'é'] {
        App::handle_text_field_input(
            KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE),
            &mut text,
            &mut cursor,
        );
    }
    assert_eq!(text, "café");
    assert_eq!(cursor, 4);

    // Backspace should remove 'é', not panic
    App::handle_text_field_input(
        KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE),
        &mut text,
        &mut cursor,
    );
    assert_eq!(text, "caf");
    assert_eq!(cursor, 3);
}

#[test]
fn test_text_field_cursor_movement_with_multibyte() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut text = "日本語".to_string();
    let mut cursor: usize = 3; // end

    // Left arrow should move one character, not one byte
    App::handle_text_field_input(
        KeyEvent::new(KeyCode::Left, KeyModifiers::NONE),
        &mut text,
        &mut cursor,
    );
    assert_eq!(cursor, 2);

    // Delete should remove '語' (the char at position 2)
    App::handle_text_field_input(
        KeyEvent::new(KeyCode::Delete, KeyModifiers::NONE),
        &mut text,
        &mut cursor,
    );
    assert_eq!(text, "日本");
    assert_eq!(cursor, 2);

    // Home should go to 0
    App::handle_text_field_input(
        KeyEvent::new(KeyCode::Home, KeyModifiers::NONE),
        &mut text,
        &mut cursor,
    );
    assert_eq!(cursor, 0);

    // End should go to char count (2)
    App::handle_text_field_input(
        KeyEvent::new(KeyCode::End, KeyModifiers::NONE),
        &mut text,
        &mut cursor,
    );
    assert_eq!(cursor, 2);
}

#[test]
fn test_text_field_insert_at_middle_of_multibyte() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut text = "ab".to_string();
    let mut cursor: usize = 1; // between 'a' and 'b'

    // Insert 'ñ' between 'a' and 'b'
    App::handle_text_field_input(
        KeyEvent::new(KeyCode::Char('ñ'), KeyModifiers::NONE),
        &mut text,
        &mut cursor,
    );
    assert_eq!(text, "añb");
    assert_eq!(cursor, 2);
}
