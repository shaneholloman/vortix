use super::helpers::centered_rect;
use crate::app::{App, AuthField, ConnectionState, InputMode, Protocol};
use crate::state::QualityLevel;
use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        canvas::{Canvas, Line as CanvasLine},
        Block, Borders, Cell, Clear, Paragraph, Row, Scrollbar, ScrollbarOrientation,
        ScrollbarState, Table,
    },
    Frame,
};

use super::widgets;
use crate::constants;
use crate::logger;
use crate::message;
use crate::theme;
use crate::utils;

/// Render the dashboard view
pub fn render(frame: &mut Frame, app: &mut App) {
    let area = frame.area();

    if area.width < constants::MIN_TERMINAL_WIDTH || area.height < constants::MIN_TERMINAL_HEIGHT {
        let msg = format!(
            "Terminal too small ({}\u{00d7}{})\nResize to at least {}\u{00d7}{}",
            area.width,
            area.height,
            constants::MIN_TERMINAL_WIDTH,
            constants::MIN_TERMINAL_HEIGHT,
        );
        frame.render_widget(
            Paragraph::new(msg)
                .alignment(Alignment::Center)
                .style(Style::default().fg(theme::ACCENT_PRIMARY)),
            centered_rect(80, 30, area),
        );
        return;
    }

    // 1. Technical Header (1 row)
    // 2. Main Content (Flexible)
    // 3. Command Footer (1 row)
    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .split(area);

    render_cockpit_header(frame, app, chunks[0]);
    widgets::footer::render_dashboard(frame, app, chunks[2]);

    // Main Content: Left Sidebar (Profiles + Details) | Right Workspace
    // Expanded sidebar from 25% to 32% for better Connection Details display
    let main_layout = Layout::horizontal([Constraint::Percentage(32), Constraint::Percentage(68)])
        .split(chunks[1]);

    // Sidebar: Profiles (Top) | Connection Details (Bottom)
    let sidebar_layout = Layout::vertical([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(main_layout[0]);

    render_profiles_sidebar(frame, app, sidebar_layout[0]);
    render_connection_details(frame, app, sidebar_layout[1]);

    // Right Workspace: Top (Chart) | Bottom (Security + Logs)
    let workspace_chunks =
        Layout::vertical([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(main_layout[1]);

    render_throughput_chart(frame, app, workspace_chunks[0]);

    // Bottom Dash: Left (Security Guard) | Right (Event Log)
    let dash_chunks = Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(workspace_chunks[1]);

    render_security_guard(frame, app, dash_chunks[0]);
    render_activity_log(frame, app, dash_chunks[1]);

    // Register Click Areas
    app.panel_areas
        .insert(crate::app::FocusedPanel::Sidebar, sidebar_layout[0]);
    app.panel_areas.insert(
        crate::app::FocusedPanel::ConnectionDetails,
        sidebar_layout[1],
    );
    app.panel_areas
        .insert(crate::app::FocusedPanel::Chart, workspace_chunks[0]);
    app.panel_areas
        .insert(crate::app::FocusedPanel::Security, dash_chunks[0]);
    app.panel_areas
        .insert(crate::app::FocusedPanel::Logs, dash_chunks[1]);

    render_overlays(frame, app);

    // Render Zoomed Panel Overlay (if active)
    if let Some(panel) = &app.zoomed_panel {
        let area = centered_rect(90, 90, frame.area());
        frame.render_widget(ratatui::widgets::Clear, area);

        // Render the zoomed panel
        match panel {
            crate::app::FocusedPanel::Sidebar => render_profiles_sidebar(frame, app, area),
            crate::app::FocusedPanel::ConnectionDetails => {
                render_connection_details(frame, app, area);
            }
            crate::app::FocusedPanel::Chart => render_throughput_chart(frame, app, area),
            crate::app::FocusedPanel::Security => render_security_guard(frame, app, area),
            crate::app::FocusedPanel::Logs => render_activity_log(frame, app, area),
        }
    }
}

fn render_overlays(frame: &mut Frame, app: &mut App) {
    match &app.input_mode {
        InputMode::DependencyError { protocol, missing } => {
            render_dependency_alert(frame, *protocol, missing);
        }
        InputMode::PermissionDenied { action } => render_permission_denied(frame, action),
        InputMode::Import { path, cursor } => render_import_overlay(frame, path, *cursor),
        InputMode::ConfirmDelete {
            name,
            confirm_selected,
            ..
        } => render_delete_confirm(frame, name, *confirm_selected),
        InputMode::AuthPrompt {
            profile_name,
            username,
            username_cursor,
            password,
            password_cursor,
            focused_field,
            save_credentials,
            connect_after,
            ..
        } => render_auth_overlay(
            frame,
            profile_name,
            username,
            *username_cursor,
            password,
            *password_cursor,
            focused_field,
            *save_credentials,
            *connect_after,
        ),
        InputMode::Rename {
            new_name, cursor, ..
        } => {
            render_rename_overlay(frame, new_name, *cursor);
        }
        InputMode::Help { scroll } => {
            super::overlays::help::render(frame, *scroll);
        }
        InputMode::Search { query, cursor } => {
            render_search_bar(frame, app, query, *cursor, app.profiles.len());
        }
        InputMode::ConfirmSwitch {
            from,
            to_name,
            confirm_selected,
            ..
        } => {
            render_confirm_switch(frame, from, to_name, *confirm_selected);
        }
        InputMode::Normal => {}
    }

    if app.show_config {
        super::overlays::config_viewer::render(frame, app);
    }

    if app.show_action_menu || app.show_bulk_menu {
        let (actions, title) = if app.show_bulk_menu {
            (message::get_bulk_actions(), " Bulk Actions ")
        } else {
            (message::get_single_actions(&app.focused_panel), " Actions ")
        };

        super::overlays::action_menu::render(frame, &actions, &mut app.action_menu_state, title);
    }
}

fn render_import_overlay(frame: &mut Frame, path: &str, cursor: usize) {
    let area = frame.area();
    let popup_layout = Layout::vertical([
        Constraint::Percentage(30),
        Constraint::Percentage(40),
        Constraint::Percentage(30),
    ])
    .split(area);

    let popup_area = Layout::horizontal([
        Constraint::Percentage(15),
        Constraint::Percentage(70),
        Constraint::Percentage(15),
    ])
    .split(popup_layout[1])[1];

    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::ACCENT_PRIMARY))
        .title(constants::TITLE_IMPORT_PROFILE)
        .title_bottom(Line::from(constants::TITLE_IMPORT_FOOTER).centered());

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let before = path.chars().take(cursor).collect::<String>();
    let cursor_char = path
        .chars()
        .nth(cursor)
        .map_or_else(|| "█".to_string(), |c| c.to_string());
    let after = path.chars().skip(cursor + 1).collect::<String>();

    let text = vec![
        Line::from(""),
        Line::from(Span::styled(
            constants::PROMPT_IMPORT_PATH,
            Style::default().fg(theme::TEXT_PRIMARY),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(" > ", Style::default().fg(theme::TEXT_SECONDARY)),
            Span::styled(before, Style::default().fg(theme::TEXT_PRIMARY)),
            Span::styled(
                cursor_char,
                Style::default()
                    .fg(theme::ACCENT_SECONDARY)
                    .add_modifier(Modifier::REVERSED)
                    .add_modifier(Modifier::SLOW_BLINK),
            ),
            Span::styled(after, Style::default().fg(theme::TEXT_PRIMARY)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            constants::HINT_IMPORT_BULK,
            Style::default().fg(theme::ACCENT_SECONDARY),
        )),
        Line::from(""),
        Line::from(Span::styled(
            constants::LABEL_SUPPORTED_FORMATS,
            Style::default().fg(theme::TEXT_SECONDARY),
        )),
        Line::from(vec![
            Span::styled(
                format!("  {}", constants::EXT_CONF),
                Style::default().fg(theme::NORD_PURPLE),
            ),
            Span::styled(
                format!(" → {}", constants::PROTO_WIREGUARD),
                Style::default().fg(theme::TEXT_SECONDARY),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                format!("  {}", constants::EXT_OVPN),
                Style::default().fg(theme::WARNING),
            ),
            Span::styled(
                format!(" → {}", constants::PROTO_OPENVPN),
                Style::default().fg(theme::TEXT_SECONDARY),
            ),
        ]),
    ];

    frame.render_widget(Paragraph::new(text).alignment(Alignment::Left), inner);
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn render_auth_overlay(
    frame: &mut Frame,
    profile_name: &str,
    username: &str,
    username_cursor: usize,
    password: &str,
    password_cursor: usize,
    focused_field: &AuthField,
    save_credentials: bool,
    connect_after: bool,
) {
    let area = frame.area();
    let popup_layout = Layout::vertical([
        Constraint::Percentage(25),
        Constraint::Percentage(50),
        Constraint::Percentage(25),
    ])
    .split(area);

    let popup_area = Layout::horizontal([
        Constraint::Percentage(20),
        Constraint::Percentage(60),
        Constraint::Percentage(20),
    ])
    .split(popup_layout[1])[1];

    frame.render_widget(Clear, popup_area);

    let (title, footer) = if connect_after {
        (constants::TITLE_AUTH_PROMPT, constants::TITLE_AUTH_FOOTER)
    } else {
        (
            constants::TITLE_AUTH_MANAGE,
            constants::TITLE_AUTH_MANAGE_FOOTER,
        )
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::ACCENT_PRIMARY))
        .title(title)
        .title_bottom(Line::from(footer).centered());

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    // Build text cursor helper
    let make_cursor_line =
        |text: &str, cursor: usize, is_focused: bool, mask: bool| -> Line<'static> {
            let display_text: String = if mask {
                "\u{25CF}".repeat(text.len()) // ● characters
            } else {
                text.to_string()
            };

            let before: String = display_text.chars().take(cursor).collect();
            let cursor_char: String = display_text
                .chars()
                .nth(cursor)
                .map_or_else(|| "\u{2588}".to_string(), |c| c.to_string()); // █
            let after: String = display_text.chars().skip(cursor + 1).collect();

            let prompt_style = if is_focused {
                Style::default().fg(theme::ACCENT_PRIMARY)
            } else {
                Style::default().fg(theme::TEXT_SECONDARY)
            };

            if is_focused {
                Line::from(vec![
                    Span::styled(" > ", prompt_style),
                    Span::styled(before, Style::default().fg(theme::TEXT_PRIMARY)),
                    Span::styled(
                        cursor_char,
                        Style::default()
                            .fg(theme::ACCENT_SECONDARY)
                            .add_modifier(Modifier::REVERSED)
                            .add_modifier(Modifier::SLOW_BLINK),
                    ),
                    Span::styled(after, Style::default().fg(theme::TEXT_PRIMARY)),
                ])
            } else {
                let full_text: String = if mask && !text.is_empty() {
                    "\u{25CF}".repeat(text.len())
                } else if text.is_empty() {
                    String::new()
                } else {
                    text.to_string()
                };
                Line::from(vec![
                    Span::styled("   ", prompt_style),
                    Span::styled(full_text, Style::default().fg(theme::INACTIVE)),
                ])
            }
        };

    // Checkbox display
    let checkbox_focused = *focused_field == AuthField::SaveCheckbox;
    let checkbox_icon = if save_credentials { "[x]" } else { "[ ]" };
    let checkbox_style = if checkbox_focused {
        Style::default()
            .fg(theme::ACCENT_PRIMARY)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme::TEXT_SECONDARY)
    };
    let checkbox_label_style = if checkbox_focused {
        Style::default().fg(theme::TEXT_PRIMARY)
    } else {
        Style::default().fg(theme::TEXT_SECONDARY)
    };

    let text = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  Profile: ", Style::default().fg(theme::TEXT_SECONDARY)),
            Span::styled(
                profile_name.to_string(),
                Style::default()
                    .fg(theme::ACCENT_PRIMARY)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" (OpenVPN)", Style::default().fg(theme::TEXT_SECONDARY)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  Username:",
            if *focused_field == AuthField::Username {
                Style::default()
                    .fg(theme::TEXT_PRIMARY)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme::TEXT_SECONDARY)
            },
        )),
        make_cursor_line(
            username,
            username_cursor,
            *focused_field == AuthField::Username,
            false,
        ),
        Line::from(""),
        Line::from(Span::styled(
            "  Password:",
            if *focused_field == AuthField::Password {
                Style::default()
                    .fg(theme::TEXT_PRIMARY)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme::TEXT_SECONDARY)
            },
        )),
        make_cursor_line(
            password,
            password_cursor,
            *focused_field == AuthField::Password,
            true,
        ),
        Line::from(""),
        Line::from(vec![
            Span::styled(format!("  {checkbox_icon} "), checkbox_style),
            Span::styled("Save credentials for future sessions", checkbox_label_style),
        ]),
    ];

    frame.render_widget(Paragraph::new(text).alignment(Alignment::Left), inner);
}

#[allow(clippy::too_many_lines)]
fn render_cockpit_header(frame: &mut Frame, app: &App, area: Rect) {
    let (status_text, color, profile_name, _location_text, _iface_text, since) =
        get_connection_info(app);

    let ks_indicator = get_killswitch_indicator(app);

    // Build header based on connection state
    let line = match &app.connection_state {
        ConnectionState::Disconnected => {
            // When disconnected, show "Real IP" label to clarify
            Line::from(vec![
                Span::styled(
                    status_text,
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(" │ ", Style::default().fg(theme::NORD_POLAR_NIGHT_4)),
                Span::styled("Your IP: ", Style::default().fg(theme::TEXT_SECONDARY)),
                Span::styled(&app.public_ip, Style::default().fg(theme::TEXT_PRIMARY)),
                Span::styled(" (Unprotected)", Style::default().fg(theme::WARNING)),
                Span::styled(" │", Style::default().fg(theme::NORD_POLAR_NIGHT_4)),
                ks_indicator,
            ])
        }
        ConnectionState::Connecting { started, .. }
        | ConnectionState::Disconnecting { started, .. } => {
            let elapsed = started.elapsed().as_secs();
            let spinner_frames = ['◐', '◓', '◑', '◒'];
            #[allow(clippy::cast_possible_truncation)]
            let spinner = spinner_frames[(elapsed as usize) % spinner_frames.len()];
            let action = if matches!(app.connection_state, ConnectionState::Connecting { .. }) {
                "CONNECTING"
            } else {
                "DISCONNECTING"
            };
            Line::from(vec![
                Span::styled(
                    format!("{spinner} {action}"),
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(" ({profile_name})"),
                    Style::default().fg(theme::TEXT_SECONDARY),
                ),
                Span::styled(
                    format!(" {elapsed}s"),
                    Style::default().fg(theme::ACCENT_SECONDARY),
                ),
                Span::styled(" │", Style::default().fg(theme::NORD_POLAR_NIGHT_4)),
                ks_indicator,
            ])
        }
        ConnectionState::Connected { .. } => {
            // Connected - show VPN IP, uptime, and quality
            let elapsed = since.map_or(0, |s| s.elapsed().as_secs());
            let uptime = if elapsed >= 86400 {
                format!(
                    "▲{}d {:02}:{:02}:{:02}",
                    elapsed / 86400,
                    (elapsed % 86400) / 3600,
                    (elapsed % 3600) / 60,
                    elapsed % 60,
                )
            } else if elapsed >= 3600 {
                format!(
                    "▲{:02}:{:02}:{:02}",
                    elapsed / 3600,
                    (elapsed % 3600) / 60,
                    elapsed % 60,
                )
            } else {
                format!("▲{:02}:{:02}", elapsed / 60, elapsed % 60)
            };

            // Connection quality indicator
            let quality_indicator = if app.latency_ms > 0 {
                match QualityLevel::from_metrics(app.packet_loss, app.jitter_ms) {
                    QualityLevel::Poor => ("●●○○○", theme::NORD_RED),
                    QualityLevel::Fair => ("●●●○○", theme::NORD_YELLOW),
                    QualityLevel::Excellent => {
                        if app.latency_ms < 50 {
                            ("●●●●●", theme::NORD_GREEN)
                        } else if app.latency_ms < 150 {
                            ("●●●●○", theme::NORD_GREEN)
                        } else {
                            ("●●●○○", theme::NORD_YELLOW)
                        }
                    }
                }
            } else {
                ("─────", theme::TEXT_SECONDARY)
            };

            let proto_tag = app
                .profiles
                .iter()
                .find(|p| p.name == profile_name)
                .map_or("", |p| match p.protocol {
                    Protocol::WireGuard => "WG",
                    Protocol::OpenVPN => "OVPN",
                });

            let proto_suffix = if proto_tag.is_empty() {
                ")".to_string()
            } else {
                format!("/{proto_tag})")
            };

            let mut header_spans = vec![
                Span::styled(
                    status_text,
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(" ({profile_name}"),
                    Style::default().fg(theme::TEXT_SECONDARY),
                ),
                Span::styled(proto_suffix, Style::default().fg(theme::NORD_FROST_2)),
                Span::styled(" │ ", Style::default().fg(theme::NORD_POLAR_NIGHT_4)),
                Span::styled("VPN: ", Style::default().fg(theme::TEXT_SECONDARY)),
                Span::styled(&app.public_ip, Style::default().fg(theme::SUCCESS)),
            ];

            // Add location if available (from real-time IP geolocation)
            if !app.location.is_empty()
                && app.location != "Unknown"
                && app.location != constants::MSG_DETECTING
            {
                // Adaptive: use ~25% of terminal width for location, min 10
                let loc_budget = (area.width as usize / 4).max(10);
                header_spans.push(Span::styled(
                    " @ ",
                    Style::default().fg(theme::TEXT_SECONDARY),
                ));
                header_spans.push(Span::styled(
                    utils::truncate(&app.location, loc_budget),
                    Style::default().fg(theme::ACCENT_PRIMARY),
                ));
            }

            header_spans.extend_from_slice(&[
                Span::styled(" │ ", Style::default().fg(theme::NORD_POLAR_NIGHT_4)),
                Span::styled(uptime, Style::default().fg(theme::ACCENT_SECONDARY)),
                Span::styled(" │ ", Style::default().fg(theme::NORD_POLAR_NIGHT_4)),
                Span::styled(
                    quality_indicator.0,
                    Style::default().fg(quality_indicator.1),
                ),
                Span::styled(" │", Style::default().fg(theme::NORD_POLAR_NIGHT_4)),
                ks_indicator,
            ]);

            Line::from(header_spans)
        }
    };

    frame.render_widget(Paragraph::new(line), area);
}

fn get_connection_info(
    app: &App,
) -> (
    &'static str,
    Color,
    &str,
    &str,
    &str,
    Option<std::time::Instant>,
) {
    match &app.connection_state {
        ConnectionState::Disconnected => {
            ("✗ DISCONNECTED", theme::ERROR, "None", "None", "-", None)
        }
        ConnectionState::Connecting { profile, .. } => {
            ("⟳ CONNECTING", theme::WARNING, profile, "...", "...", None)
        }
        ConnectionState::Disconnecting { profile, .. } => (
            "⏻ DISCONNECTING",
            theme::WARNING,
            profile,
            "...",
            "...",
            None,
        ),
        ConnectionState::Connected {
            profile,
            since,
            details,
            ..
        } => (
            "✓ CONNECTED",
            theme::SUCCESS,
            profile,
            &app.location,
            &details.interface,
            Some(*since),
        ),
    }
}

/// Get kill switch indicator for the header bar.
/// Self-explanatory labels: KS:Off, KS:Auto, KS:Strict, KS:BLOCK
fn get_killswitch_indicator(app: &App) -> Span<'static> {
    use crate::state::{KillSwitchMode, KillSwitchState};

    match (app.killswitch_mode, app.killswitch_state) {
        // Kill switch is OFF
        (KillSwitchMode::Off, _) | (_, KillSwitchState::Disabled) => {
            Span::styled(" KS:Off ", Style::default().fg(theme::INACTIVE))
        }
        // BLOCKING - critical state, user needs to know internet is blocked
        (_, KillSwitchState::Blocking) => Span::styled(
            " KS:BLOCK ",
            Style::default()
                .fg(theme::ERROR)
                .add_modifier(Modifier::BOLD),
        ),
        // Auto mode - armed and monitoring
        (KillSwitchMode::Auto, KillSwitchState::Armed) => {
            Span::styled(" KS:Auto ", Style::default().fg(theme::SUCCESS))
        }
        // Strict mode - armed and monitoring
        (KillSwitchMode::AlwaysOn, KillSwitchState::Armed) => {
            Span::styled(" KS:Strict ", Style::default().fg(theme::WARNING))
        }
    }
}

#[allow(clippy::too_many_lines)]
fn render_profiles_sidebar(frame: &mut Frame, app: &mut App, area: Rect) {
    let is_focused = app.should_draw_focus(&crate::app::FocusedPanel::Sidebar);
    let border_style = if is_focused {
        Style::default().fg(theme::BORDER_FOCUSED)
    } else {
        Style::default().fg(theme::BORDER_DEFAULT)
    };

    let sort_label = app.sort_order.label();
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(format!(" Profiles [{sort_label}] "));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if app.profiles.is_empty() {
        let empty_msg = vec![
            Line::from(""),
            Line::from(Span::styled(
                "No profiles yet",
                Style::default().fg(theme::TEXT_SECONDARY),
            )),
            Line::from(""),
            Line::from(vec![
                Span::styled("Press ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    "[i]",
                    Style::default()
                        .fg(theme::ACCENT_PRIMARY)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(" to import", Style::default().fg(Color::DarkGray)),
            ]),
        ];
        frame.render_widget(
            Paragraph::new(empty_msg).alignment(Alignment::Center),
            inner,
        );
        return;
    }

    let (active_profile, active_color) = match &app.connection_state {
        ConnectionState::Connected { profile, .. } => (Some(profile.clone()), theme::SUCCESS),
        ConnectionState::Connecting { profile, .. }
        | ConnectionState::Disconnecting { profile, .. } => (Some(profile.clone()), theme::WARNING),
        ConnectionState::Disconnected => (None, Color::Reset),
    };

    let items: Vec<Row> = app
        .profiles
        .iter()
        .enumerate()
        .map(|(idx, p)| {
            let is_selected = app.profile_list_state.selected() == Some(idx);
            let is_active = active_profile.as_ref() == Some(&p.name);
            let is_never_used = p.last_used.is_none();

            let (status_char, status_color) = if is_active {
                ("●".to_string(), active_color)
            } else if idx < 9 {
                (format!("{}", idx + 1), theme::TEXT_SECONDARY)
            } else {
                (" ".to_string(), Color::Reset)
            };

            let name_style = if is_selected && is_active {
                Style::default()
                    .fg(active_color)
                    .add_modifier(Modifier::BOLD)
            } else if is_selected {
                Style::default()
                    .fg(theme::ROW_SELECTED_FG)
                    .add_modifier(Modifier::BOLD)
            } else if is_active {
                Style::default().fg(active_color)
            } else if is_never_used {
                Style::default().fg(Color::DarkGray)
            } else {
                Style::default().fg(theme::INACTIVE)
            };

            let proto_icon = match p.protocol {
                crate::app::Protocol::WireGuard => "WG",
                crate::app::Protocol::OpenVPN => "OV",
            };
            let proto_color = if is_active {
                active_color
            } else if is_selected {
                theme::ACCENT_PRIMARY
            } else {
                theme::TEXT_SECONDARY
            };

            // Last used time
            let time_str = if let Some(last_used) = p.last_used {
                let relative = utils::format_relative_time(last_used);
                if !relative.ends_with("ago") && !relative.is_empty() {
                    format!("{relative} ago")
                } else {
                    relative
                }
            } else {
                "never".to_string()
            };

            let row_style = if is_selected {
                Style::default().bg(theme::ROW_SELECTED_BG)
            } else {
                Style::default()
            };

            // Create cells for each column
            let status_cell = Cell::from(Span::styled(
                status_char.clone(),
                Style::default().fg(status_color),
            ));
            let state_badge = if is_active {
                match &app.connection_state {
                    ConnectionState::Connected { .. } => " ✓",
                    ConnectionState::Connecting { .. } => " …",
                    ConnectionState::Disconnecting { .. } => " ⏻",
                    ConnectionState::Disconnected => "",
                }
            } else {
                ""
            };
            let name_cell = Cell::from(Line::from(vec![
                Span::styled(p.name.clone(), name_style),
                Span::styled(state_badge, Style::default().fg(active_color)),
            ]));
            let proto_cell = Cell::from(Span::styled(proto_icon, Style::default().fg(proto_color)));
            let time_cell =
                Cell::from(Span::styled(time_str, Style::default().fg(Color::DarkGray)));

            Row::new(vec![status_cell, name_cell, proto_cell, time_cell]).style(row_style)
        })
        .collect();

    let table = Table::new(
        items,
        [
            Constraint::Length(2),  // Status column (● or space)
            Constraint::Min(8),     // Profile name (flexible)
            Constraint::Length(4),  // Protocol (WG/OV)
            Constraint::Length(10), // Last used time
        ],
    );
    frame.render_stateful_widget(table, inner, &mut app.profile_list_state);

    // Scrollbar Logic
    let scrollbar = Scrollbar::default()
        .orientation(ScrollbarOrientation::VerticalRight)
        .begin_symbol(Some("↑"))
        .end_symbol(Some("↓"))
        .style(Style::default().fg(theme::NORD_POLAR_NIGHT_4))
        .thumb_style(Style::default().fg(theme::ACCENT_PRIMARY));

    let mut scrollbar_state =
        ScrollbarState::new(app.profiles.len().saturating_sub(inner.height as usize))
            .position(app.profile_list_state.selected().unwrap_or(0));

    frame.render_stateful_widget(
        scrollbar,
        area.inner(ratatui::layout::Margin {
            vertical: 1,
            horizontal: 0,
        }),
        &mut scrollbar_state,
    );
}

#[allow(clippy::too_many_lines)]
fn render_throughput_chart(frame: &mut Frame, app: &App, area: Rect) {
    let is_focused = app.should_draw_focus(&crate::app::FocusedPanel::Chart);
    let border_style = if is_focused {
        Style::default().fg(theme::BORDER_FOCUSED)
    } else {
        Style::default().fg(theme::BORDER_DEFAULT)
    };

    // Peak detection for dynamic Y-axis scaling (calculate first for title)
    let max_down = app.down_history.iter().map(|(_, y)| *y).fold(0.0, f64::max);
    let max_up = app.up_history.iter().map(|(_, y)| *y).fold(0.0, f64::max);
    let peak = (max_down.max(max_up) * 1.2).max(1024.0 * 1024.0 * 0.5);
    let (scale_val, scale_unit) = if peak >= 1024.0 * 1024.0 * 1024.0 {
        (peak / 1024.0 / 1024.0 / 1024.0, "GB/s")
    } else if peak >= 1024.0 * 1024.0 {
        (peak / 1024.0 / 1024.0, "MB/s")
    } else {
        (peak / 1024.0, "KB/s")
    };
    let peak_label = format!(" Peak: {scale_val:.1} {scale_unit} ");

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(" Network Throughput ")
        .title(
            Line::from(Span::styled(
                peak_label,
                Style::default().fg(theme::NORD_POLAR_NIGHT_4),
            ))
            .right_aligned(),
        )
        .title_bottom(
            Line::from(Span::styled(
                format!(" Scale: 0 – {scale_val:.1} {scale_unit} "),
                Style::default().fg(Color::DarkGray),
            ))
            .right_aligned(),
        );

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Layout: Stats+Legend (Top) | Chart (Bottom)
    let chunks = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).split(inner);

    let is_disconnected = !matches!(app.connection_state, ConnectionState::Connected { .. });
    let has_data = app.down_history.len() > 1 || app.up_history.len() > 1;

    // Calculate session totals from connection details if available
    let (session_rx, session_tx) = match &app.connection_state {
        ConnectionState::Connected { details, .. } => {
            let rx = if details.transfer_rx.is_empty() {
                "0B".to_string()
            } else {
                details.transfer_rx.clone()
            };
            let tx = if details.transfer_tx.is_empty() {
                "0B".to_string()
            } else {
                details.transfer_tx.clone()
            };
            (rx, tx)
        }
        _ => ("0B".to_string(), "0B".to_string()),
    };

    let stats_line = Line::from(vec![
        Span::styled(" ▬", Style::default().fg(theme::SUCCESS)),
        Span::styled(" UP: ", Style::default().fg(theme::TEXT_SECONDARY)),
        Span::styled(
            format!("{:<10}", utils::format_bytes_speed(app.current_up)),
            Style::default().fg(theme::TEXT_PRIMARY),
        ),
        Span::styled(" ▬", Style::default().fg(theme::ACCENT_PRIMARY)),
        Span::styled(" DOWN: ", Style::default().fg(theme::TEXT_SECONDARY)),
        Span::styled(
            format!("{:<10}", utils::format_bytes_speed(app.current_down)),
            Style::default().fg(theme::TEXT_PRIMARY),
        ),
        Span::styled(" │ ", Style::default().fg(theme::NORD_POLAR_NIGHT_4)),
        Span::styled(" Session: ", Style::default().fg(theme::TEXT_SECONDARY)),
        Span::styled("↓", Style::default().fg(theme::NORD_FROST_3)),
        Span::styled(&session_rx, Style::default().fg(theme::TEXT_PRIMARY)),
        Span::styled(" ↑", Style::default().fg(theme::NORD_GREEN)),
        Span::styled(&session_tx, Style::default().fg(theme::TEXT_PRIMARY)),
    ]);
    frame.render_widget(
        Paragraph::new(stats_line).alignment(Alignment::Center),
        chunks[0],
    );

    if is_disconnected && !has_data {
        let empty_msg = Paragraph::new(Line::from(Span::styled(
            "Connect to see throughput",
            Style::default().fg(theme::TEXT_SECONDARY),
        )))
        .alignment(Alignment::Center);
        frame.render_widget(empty_msg, chunks[1]);
    } else {
        let canvas = Canvas::default()
            .block(Block::default())
            .x_bounds([0.0, 60.0])
            .y_bounds([0.0, peak])
            .paint(|ctx| {
                if app.down_history.len() > 1 {
                    for i in 0..app.down_history.len() - 1 {
                        let y1 = app.down_history[i].1;
                        let y2 = app.down_history[i + 1].1;
                        if y1 > 0.0 || y2 > 0.0 {
                            ctx.draw(&CanvasLine {
                                x1: app.down_history[i].0,
                                y1,
                                x2: app.down_history[i + 1].0,
                                y2,
                                color: theme::ACCENT_PRIMARY,
                            });
                        }
                    }
                }
                if app.up_history.len() > 1 {
                    for i in 0..app.up_history.len() - 1 {
                        let y1 = app.up_history[i].1;
                        let y2 = app.up_history[i + 1].1;
                        if y1 > 0.0 || y2 > 0.0 {
                            ctx.draw(&CanvasLine {
                                x1: app.up_history[i].0,
                                y1,
                                x2: app.up_history[i + 1].0,
                                y2,
                                color: theme::SUCCESS,
                            });
                        }
                    }
                }
            });
        frame.render_widget(canvas, chunks[1]);
    }
}

#[allow(clippy::too_many_lines)]
fn render_security_guard(frame: &mut Frame, app: &App, area: Rect) {
    let is_focused = app.should_draw_focus(&crate::app::FocusedPanel::Security);
    let border_style = if is_focused {
        Style::default().fg(theme::BORDER_FOCUSED)
    } else {
        Style::default().fg(theme::BORDER_DEFAULT)
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(" Security Guard ");

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Security checks
    let is_connected = !matches!(app.connection_state, ConnectionState::Disconnected);
    let ipv6_leaking = app.ipv6_leak;

    if !is_connected {
        // Disconnected state - show warning
        let audit = vec![
            Line::from(vec![Span::styled(
                " ⚠ EXPOSED ",
                Style::default()
                    .bg(theme::WARNING)
                    .fg(Color::Black)
                    .add_modifier(Modifier::BOLD),
            )]),
            Line::from(""),
            Line::from(Span::styled(
                "Your traffic is unencrypted.",
                Style::default().fg(theme::TEXT_SECONDARY),
            )),
            Line::from(Span::styled(
                "Connect to a VPN profile.",
                Style::default().fg(theme::TEXT_SECONDARY),
            )),
        ];
        frame.render_widget(Paragraph::new(audit), inner);
        return;
    }

    // DNS leak: if current DNS matches the pre-VPN DNS, queries may not be tunneled.
    // A changed DNS (even private like 10.8.0.1) means the VPN pushed its own resolver.
    let dns_leaking = match &app.real_dns {
        Some(real_dns) => &app.dns_server == real_dns,
        None => false, // can't determine yet, assume OK
    };

    // Check if IP is actually masked (different from real IP captured when disconnected)
    let ip_status = match &app.real_ip {
        Some(real)
            if !app.public_ip.is_empty()
                && app.public_ip != constants::MSG_DETECTING
                && app.public_ip != constants::MSG_FETCHING
                && !app.public_ip.starts_with("Error") =>
        {
            if &app.public_ip == real {
                (false, true, Some(real.clone())) // LEAK! same IP as real
            } else {
                (true, false, Some(real.clone())) // masked (different IP)
            }
        }
        _ => (false, false, None), // unknown (still checking)
    };
    let (ip_masked, ip_leaking, real_ip_opt) = ip_status;

    // Get encryption info from connection details
    let encryption_info = match &app.connection_state {
        ConnectionState::Connected { details, .. } => {
            if details.public_key == "OpenVPN" || details.public_key.is_empty() {
                // OpenVPN
                if details.latest_handshake.starts_with("Cipher:") {
                    details.latest_handshake.replace("Cipher: ", "")
                } else {
                    "AES-256-GCM".to_string()
                }
            } else {
                // WireGuard
                "ChaCha20-Poly1305".to_string()
            }
        }
        _ => "N/A".to_string(),
    };

    // Security checklist with pass/fail indicators
    let check_pass = Span::styled("✓ ", Style::default().fg(theme::SUCCESS));
    let check_fail = Span::styled("✗ ", Style::default().fg(theme::ERROR));
    let check_warn = Span::styled("● ", Style::default().fg(theme::WARNING));

    // Truncate values to fit panel
    let max_val = inner.width.saturating_sub(15) as usize;

    let mut audit = vec![
        Line::from(vec![Span::styled(
            "   PROTECTED",
            Style::default()
                .fg(if ip_masked && !dns_leaking && !ipv6_leaking {
                    theme::SUCCESS
                } else {
                    theme::WARNING
                })
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
    ];

    // IP Masked - show both masked and real
    if let Some(real_ip) = real_ip_opt {
        audit.push(Line::from(vec![
            if ip_masked {
                check_pass.clone()
            } else if ip_leaking {
                check_fail.clone()
            } else {
                check_warn.clone()
            },
            Span::styled("IP Masked  : ", Style::default().fg(theme::TEXT_SECONDARY)),
            Span::styled(
                utils::truncate(&app.public_ip, max_val),
                Style::default().fg(if ip_masked {
                    theme::SUCCESS
                } else {
                    theme::ERROR
                }),
            ),
        ]));
        audit.push(Line::from(vec![
            Span::styled("  Real IP: ", Style::default().fg(theme::TEXT_SECONDARY)),
            Span::styled(
                format!("{real_ip} (hidden)"),
                Style::default().fg(Color::DarkGray),
            ),
        ]));
    } else {
        audit.push(Line::from(vec![
            check_warn.clone(),
            Span::styled("IP Masked  : ", Style::default().fg(theme::TEXT_SECONDARY)),
            Span::styled("Checking...", Style::default().fg(theme::WARNING)),
        ]));
    }

    audit.push(Line::from(""));

    // DNS Check with provider name if possible
    let dns_provider = if app.dns_server.contains("1.1.1.1") {
        " (Cloudflare)"
    } else if app.dns_server.contains("8.8.8.8") || app.dns_server.contains("8.8.4.4") {
        " (Google)"
    } else if app.dns_server.contains("9.9.9.9") {
        " (Quad9)"
    } else {
        ""
    };

    audit.push(Line::from(vec![
        if dns_leaking {
            check_fail.clone()
        } else {
            check_pass.clone()
        },
        Span::styled("DNS Secure : ", Style::default().fg(theme::TEXT_SECONDARY)),
        Span::styled(
            utils::truncate(&app.dns_server, max_val),
            Style::default().fg(if dns_leaking {
                theme::ERROR
            } else {
                theme::SUCCESS
            }),
        ),
    ]));
    if !dns_provider.is_empty() {
        audit.push(Line::from(vec![
            Span::styled("  Provider: ", Style::default().fg(theme::TEXT_SECONDARY)),
            Span::styled(dns_provider, Style::default().fg(Color::DarkGray)),
        ]));
    }
    if let Some(real_dns) = &app.real_dns {
        if dns_leaking {
            let real_dns_display = format!("{real_dns} (same!)");
            audit.push(Line::from(vec![
                Span::styled("  Pre-VPN : ", Style::default().fg(theme::TEXT_SECONDARY)),
                Span::styled(
                    utils::truncate(&real_dns_display, max_val),
                    Style::default().fg(theme::ERROR),
                ),
            ]));
        }
    }

    audit.push(Line::from(""));

    // IPv6 Check
    audit.push(Line::from(vec![
        if ipv6_leaking {
            check_fail.clone()
        } else {
            check_pass.clone()
        },
        Span::styled("IPv6       : ", Style::default().fg(theme::TEXT_SECONDARY)),
        Span::styled(
            if ipv6_leaking { "Leaking" } else { "Blocked" },
            Style::default().fg(if ipv6_leaking {
                theme::ERROR
            } else {
                theme::SUCCESS
            }),
        ),
    ]));

    audit.push(Line::from(""));

    // Kill Switch Status
    let (ks_icon, ks_text, ks_color) = match (app.killswitch_mode, app.killswitch_state) {
        (crate::state::KillSwitchMode::Off, _) => (check_fail.clone(), "Off", theme::INACTIVE),
        (_, crate::state::KillSwitchState::Blocking) => {
            (check_warn.clone(), "Blocking (Strict)", theme::ERROR)
        }
        (crate::state::KillSwitchMode::Auto, crate::state::KillSwitchState::Armed) => {
            (check_pass.clone(), "Armed (Auto)", theme::SUCCESS)
        }
        (crate::state::KillSwitchMode::AlwaysOn, crate::state::KillSwitchState::Armed) => {
            (check_pass.clone(), "Armed (Strict)", theme::WARNING)
        }
        _ => (check_warn.clone(), "Unknown", theme::WARNING),
    };

    audit.push(Line::from(vec![
        ks_icon,
        Span::styled("Kill Switch: ", Style::default().fg(theme::TEXT_SECONDARY)),
        Span::styled(ks_text, Style::default().fg(ks_color)),
    ]));

    audit.push(Line::from(""));

    // Encryption Info
    audit.push(Line::from(vec![
        check_pass,
        Span::styled("Encryption : ", Style::default().fg(theme::TEXT_SECONDARY)),
        Span::styled(encryption_info, Style::default().fg(theme::NORD_YELLOW)),
    ]));

    let last_checked_text = match app.last_security_check {
        Some(t) => {
            let secs = t.elapsed().as_secs();
            if secs < 5 {
                "Last checked: just now".to_string()
            } else if secs < 60 {
                format!("Last checked: {secs}s ago")
            } else {
                format!("Last checked: {}m ago", secs / 60)
            }
        }
        None => "Last checked: pending...".to_string(),
    };
    audit.push(Line::from(""));
    audit.push(Line::from(vec![Span::styled(
        last_checked_text,
        Style::default().fg(Color::DarkGray),
    )]));

    let available_height = inner.height as usize;
    if available_height > 0 && audit.len() > available_height {
        let mut compacted = Vec::with_capacity(available_height);
        let mut blank_budget = 2usize;

        for line in audit {
            let is_blank =
                line.spans.is_empty() || line.spans.iter().all(|s| s.content.trim().is_empty());
            if is_blank {
                if blank_budget == 0 {
                    continue;
                }
                blank_budget -= 1;
            }
            compacted.push(line);
            if compacted.len() == available_height {
                break;
            }
        }
        audit = compacted;
    }

    frame.render_widget(Paragraph::new(audit), inner);
}

fn render_dependency_alert(frame: &mut Frame, protocol: Protocol, missing: &[String]) {
    let area = frame.area();
    let popup_layout = Layout::vertical([
        Constraint::Percentage(25),
        Constraint::Percentage(50),
        Constraint::Percentage(25),
    ])
    .split(area);

    let popup_area = Layout::horizontal([
        Constraint::Percentage(25),
        Constraint::Percentage(50),
        Constraint::Percentage(25),
    ])
    .split(popup_layout[1])[1];

    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red))
        .title(" System Dependency Missing ");

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let chunks = Layout::vertical([
        Constraint::Min(0),
        Constraint::Length(8),
        Constraint::Min(0),
    ])
    .split(inner);

    let pkg = if protocol == Protocol::WireGuard {
        "wireguard-tools"
    } else {
        "openvpn"
    };

    let text = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(
                " ERROR: ",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "Missing system tools required for {protocol} sessions."
            )),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::raw(" Missing: "),
            Span::styled(missing.join(", "), Style::default().fg(Color::Yellow)),
        ]),
        Line::from(""),
        Line::from(vec![Span::raw(
            " To fix this, please run the following in your terminal:",
        )]),
        Line::from(vec![Span::styled(
            format!(" {}", crate::platform::install_hint(pkg)),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::raw(" Press "),
            Span::styled(
                "[Esc]",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" to return to dashboard."),
        ]),
    ];

    frame.render_widget(Paragraph::new(text).alignment(Alignment::Center), chunks[1]);
}

fn render_permission_denied(frame: &mut Frame, action: &str) {
    let area = frame.area();
    let popup_layout = Layout::vertical([
        Constraint::Percentage(25),
        Constraint::Percentage(50),
        Constraint::Percentage(25),
    ])
    .split(area);

    let popup_area = Layout::horizontal([
        Constraint::Percentage(25),
        Constraint::Percentage(50),
        Constraint::Percentage(25),
    ])
    .split(popup_layout[1])[1];

    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red))
        .title(" Elevated Privileges Required ");

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let chunks = Layout::vertical([
        Constraint::Min(0),
        Constraint::Length(8),
        Constraint::Min(0),
    ])
    .split(inner);

    let text = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(
                " ACCESS DENIED: ",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "{} needs root privileges to {action}.",
                constants::APP_NAME
            )),
        ]),
        Line::from(""),
        Line::from(vec![Span::raw(
            " VPN management involves modifying network interfaces and routes,",
        )]),
        Line::from(vec![Span::raw(" which is a privileged system operation.")]),
        Line::from(""),
        Line::from(vec![
            Span::raw(format!(
                " Recommendation: Restart {} with ",
                constants::APP_NAME
            )),
            Span::styled(
                format!("sudo {}", constants::APP_NAME),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::raw(" Press "),
            Span::styled(
                "[Esc]",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" to return to dashboard."),
        ]),
    ];

    frame.render_widget(Paragraph::new(text).alignment(Alignment::Center), chunks[1]);
}

fn render_delete_confirm(frame: &mut Frame, name: &str, confirm_selected: bool) {
    let area = frame.area();
    let popup_layout = Layout::vertical([
        Constraint::Percentage(40),
        Constraint::Percentage(20),
        Constraint::Percentage(40),
    ])
    .split(area);

    let popup_area = Layout::horizontal([
        Constraint::Percentage(25),
        Constraint::Percentage(50),
        Constraint::Percentage(25),
    ])
    .split(popup_layout[1])[1];

    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::ERROR))
        .title(" Confirm Deletion ");

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let yes_style = if confirm_selected {
        Style::default()
            .bg(theme::ROW_SELECTED_BG)
            .fg(theme::ROW_SELECTED_FG)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme::ROW_SELECTED_FG)
    };

    let no_style = if confirm_selected {
        Style::default().fg(theme::NORD_POLAR_NIGHT_4)
    } else {
        Style::default()
            .bg(theme::NORD_POLAR_NIGHT_4)
            .fg(Color::White)
            .add_modifier(Modifier::BOLD)
    };

    let text = vec![
        Line::from(""),
        Line::from(vec![
            Span::raw("Are you sure you want to delete "),
            Span::styled(
                name,
                Style::default()
                    .fg(theme::ACCENT_PRIMARY)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("?"),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(" [Y] Yes, Delete ", yes_style),
            Span::raw("    "),
            Span::styled(" [N] Cancel ", no_style),
        ]),
    ];

    frame.render_widget(Paragraph::new(text).alignment(Alignment::Center), inner);
}

#[allow(clippy::too_many_lines)]
fn render_activity_log(frame: &mut Frame, app: &App, area: Rect) {
    let is_focused = app.should_draw_focus(&crate::app::FocusedPanel::Logs);
    let border_style = if is_focused {
        Style::default().fg(theme::BORDER_FOCUSED)
    } else {
        Style::default().fg(theme::BORDER_DEFAULT)
    };

    let filter_label = match app.log_level_filter {
        Some(logger::LogLevel::Error) => " Err",
        Some(logger::LogLevel::Warning) => " Warn+",
        Some(logger::LogLevel::Info) => " Info+",
        None | Some(_) => "",
    };

    let title = if app.logs_auto_scroll {
        format!(" Event Log [Live{filter_label}] ")
    } else {
        format!(" Event Log [Paused{filter_label}] ")
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(title);

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let raw_logs = logger::get_logs();
    let all_logs: Vec<_> = if let Some(min_level) = app.log_level_filter {
        raw_logs
            .into_iter()
            .filter(|e| e.level >= min_level)
            .collect()
    } else {
        raw_logs
    };

    if all_logs.is_empty() {
        frame.render_widget(
            Paragraph::new("No activity yet").alignment(Alignment::Center),
            inner,
        );
        return;
    }

    // Calculate how many logs we can show (1 log per line, no wrapping)
    let visible_lines = inner.height as usize;

    // Get the last N logs that fit in the panel (auto-scroll behavior)
    let start_idx = if app.logs_auto_scroll {
        all_logs.len().saturating_sub(visible_lines)
    } else {
        (app.logs_scroll as usize).min(all_logs.len().saturating_sub(1))
    };

    let end_idx = (start_idx + visible_lines).min(all_logs.len());

    let logs: Vec<Line> = all_logs[start_idx..end_idx]
        .iter()
        .map(|entry| {
            // Format: [HH:MM:SS] LEVEL  CATEGORY  message
            let time_str = utils::format_system_time_local(entry.timestamp);
            let level_tag = entry.level.prefix(); // "INFO ", "WARN ", "ERROR", "DEBUG"

            // Fixed-width category for alignment
            let cat = format!(
                "{:<width$}",
                entry.category,
                width = constants::LOG_CATEGORY_WIDTH
            );

            // Build the message portion
            let message = &entry.message;

            // Truncate to fit available width after the structured prefix.
            // Use char boundaries to avoid panicking on multi-byte UTF-8.
            let max_msg_len = (inner.width as usize).saturating_sub(constants::LOG_PREFIX_WIDTH);
            let truncated_msg = if message.len() > max_msg_len {
                let mut end = max_msg_len.saturating_sub(1);
                while end > 0 && !message.is_char_boundary(end) {
                    end -= 1;
                }
                format!("{}…", &message[..end])
            } else {
                message.clone()
            };

            // Level badge color
            let level_style = match entry.level {
                logger::LogLevel::Error => Style::default().fg(theme::ERROR),
                logger::LogLevel::Warning => Style::default().fg(theme::WARNING),
                logger::LogLevel::Info => Style::default().fg(theme::NORD_FROST_3),
                logger::LogLevel::Debug => Style::default().fg(Color::DarkGray),
            };

            // Message color (same level-based, with info sub-coloring)
            let msg_style = match entry.level {
                logger::LogLevel::Error => Style::default().fg(theme::ERROR),
                logger::LogLevel::Warning => Style::default().fg(theme::WARNING),
                logger::LogLevel::Info => {
                    if entry.message.contains("Connected") || entry.message.contains("secure") {
                        Style::default().fg(theme::SUCCESS)
                    } else {
                        Style::default().fg(theme::INACTIVE)
                    }
                }
                logger::LogLevel::Debug => Style::default().fg(Color::DarkGray),
            };

            Line::from(vec![
                Span::styled(
                    format!("[{time_str}] "),
                    Style::default().fg(theme::TEXT_SECONDARY),
                ),
                Span::styled(format!("{level_tag} "), level_style),
                Span::styled(
                    format!("{cat}  "),
                    Style::default().fg(theme::NORD_POLAR_NIGHT_4),
                ),
                Span::styled(truncated_msg, msg_style),
            ])
        })
        .collect();

    frame.render_widget(Paragraph::new(logs), inner);

    // Scrollbar Logic
    let scrollbar = Scrollbar::default()
        .orientation(ScrollbarOrientation::VerticalRight)
        .begin_symbol(Some("↑"))
        .end_symbol(Some("↓"))
        .style(Style::default().fg(theme::NORD_POLAR_NIGHT_4))
        .thumb_style(Style::default().fg(theme::ACCENT_PRIMARY));

    let mut scrollbar_state =
        ScrollbarState::new(all_logs.len().saturating_sub(visible_lines)).position(start_idx);

    frame.render_stateful_widget(
        scrollbar,
        area.inner(ratatui::layout::Margin {
            vertical: 1,
            horizontal: 0,
        }),
        &mut scrollbar_state,
    );
}

// === Helper Utilities ===

#[allow(clippy::too_many_lines, clippy::similar_names)]
fn render_connection_details(frame: &mut Frame, app: &App, area: Rect) {
    let is_focused = app.should_draw_focus(&crate::app::FocusedPanel::ConnectionDetails);
    let border_style = if is_focused {
        Style::default().fg(theme::BORDER_FOCUSED)
    } else {
        Style::default().fg(theme::BORDER_DEFAULT)
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(" Connection Details ");

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if let ConnectionState::Connected { details, .. } = &app.connection_state {
        let is_openvpn = details.public_key == "OpenVPN" || details.public_key.is_empty();

        // MTU value
        let mtu_str = if details.mtu.is_empty() {
            "-".to_string()
        } else {
            details.mtu.clone()
        };

        let mut text = vec![
            // Row 1: VPN IP @ Interface
            Line::from(vec![
                Span::styled("VPN IP  : ", Style::default().fg(theme::TEXT_SECONDARY)),
                Span::styled(
                    &details.internal_ip,
                    Style::default()
                        .fg(theme::ACCENT_PRIMARY)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(
                        " @ {}",
                        if details.interface.is_empty() {
                            "-"
                        } else {
                            &details.interface
                        }
                    ),
                    Style::default().fg(theme::TEXT_SECONDARY),
                ),
            ]),
            // Row 2: Server (clearer than "Remote")
            Line::from(vec![
                Span::styled("Server  : ", Style::default().fg(theme::TEXT_SECONDARY)),
                Span::styled(&details.endpoint, Style::default().fg(theme::TEXT_PRIMARY)),
            ]),
            // Row 3: Exit Node (ISP | Location) — adaptive truncation
            {
                let label_overhead = 10 + 2 + 1; // "Exit    : " + " (" + ")"
                let available = (inner.width as usize).saturating_sub(label_overhead);
                let isp_max = available * 60 / 100;
                let loc_max = available.saturating_sub(isp_max);
                Line::from(vec![
                    Span::styled("Exit    : ", Style::default().fg(theme::TEXT_SECONDARY)),
                    Span::styled(
                        utils::truncate(&app.isp, isp_max.max(5)),
                        Style::default().fg(theme::TEXT_PRIMARY),
                    ),
                    Span::styled(" (", Style::default().fg(theme::TEXT_SECONDARY)),
                    Span::styled(
                        utils::truncate(&app.location, loc_max.max(5)),
                        Style::default().fg(theme::TEXT_PRIMARY),
                    ),
                    Span::styled(")", Style::default().fg(theme::TEXT_SECONDARY)),
                ])
            },
        ];

        // Row 4: Crypto/Protocol Info
        let (proto_label, proto_value, proto_color) = if is_openvpn {
            let cipher = if details.latest_handshake.starts_with("Cipher:") {
                details.latest_handshake.replace("Cipher: ", "")
            } else if details.latest_handshake.is_empty() {
                "AES-256-GCM".to_string()
            } else {
                details.latest_handshake.clone()
            };
            ("Crypto  : ", cipher, theme::NORD_YELLOW)
        } else {
            // For WireGuard, show last handshake time
            let handshake_str = if details.latest_handshake.is_empty() {
                "ChaCha20-Poly1305".to_string()
            } else {
                format!("ChaCha20 ({})", details.latest_handshake)
            };
            ("Crypto  : ", handshake_str, theme::NORD_YELLOW)
        };

        text.push(Line::from(vec![
            Span::styled(proto_label, Style::default().fg(theme::TEXT_SECONDARY)),
            Span::styled(
                if proto_value.is_empty() {
                    "-"
                } else {
                    &proto_value
                },
                Style::default().fg(proto_color),
            ),
        ]));

        // Row 5: Transfer Stats with MTU
        text.push(Line::from(vec![
            Span::styled("Transfer: ", Style::default().fg(theme::TEXT_SECONDARY)),
            Span::styled("↓", Style::default().fg(theme::NORD_FROST_3)),
            Span::styled(
                if details.transfer_rx.is_empty() {
                    "0"
                } else {
                    &details.transfer_rx
                },
                Style::default().fg(theme::TEXT_PRIMARY),
            ),
            Span::styled(" ↑", Style::default().fg(theme::NORD_GREEN)),
            Span::styled(
                if details.transfer_tx.is_empty() {
                    "0"
                } else {
                    &details.transfer_tx
                },
                Style::default().fg(theme::TEXT_PRIMARY),
            ),
            Span::styled(" (MTU:", Style::default().fg(theme::TEXT_SECONDARY)),
            Span::styled(mtu_str, Style::default().fg(theme::TEXT_SECONDARY)),
            Span::styled(")", Style::default().fg(theme::TEXT_SECONDARY)),
        ]));

        text.push(Line::from(""));

        // Row 6: Quality Metrics (Unified high-density)
        let quality_status = match QualityLevel::from_metrics(app.packet_loss, app.jitter_ms) {
            QualityLevel::Poor => ("POOR", theme::NORD_RED),
            QualityLevel::Fair => ("FAIR", theme::NORD_YELLOW),
            QualityLevel::Excellent => ("EXCELLENT", theme::NORD_GREEN),
        };

        text.push(Line::from(vec![
            Span::styled("Quality: ", Style::default().fg(theme::TEXT_SECONDARY)),
            Span::styled(
                quality_status.0,
                Style::default()
                    .fg(quality_status.1)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));

        let latency_color = if app.latency_ms < 50 {
            theme::NORD_GREEN
        } else if app.latency_ms < 150 {
            theme::NORD_YELLOW
        } else {
            theme::NORD_RED
        };
        text.push(Line::from(vec![
            Span::styled(
                "  ├─ Ping (Latency)   : ",
                Style::default().fg(theme::TEXT_SECONDARY),
            ),
            Span::styled(
                format!("{}ms", app.latency_ms),
                Style::default().fg(latency_color),
            ),
        ]));

        let jitter_color = if app.jitter_ms < 5 {
            theme::NORD_GREEN
        } else if app.jitter_ms < 15 {
            theme::NORD_YELLOW
        } else {
            theme::NORD_RED
        };
        text.push(Line::from(vec![
            Span::styled(
                "  ├─ Stability (Jitter): ",
                Style::default().fg(theme::TEXT_SECONDARY),
            ),
            Span::styled(
                format!("±{}ms", app.jitter_ms),
                Style::default().fg(jitter_color),
            ),
        ]));

        text.push(Line::from(vec![
            Span::styled(
                "  └─ Reliability (Loss): ",
                Style::default().fg(theme::TEXT_SECONDARY),
            ),
            Span::styled(
                format!("{:.1}%", app.packet_loss),
                Style::default().fg(if app.packet_loss < 1.0 {
                    theme::NORD_GREEN
                } else {
                    theme::NORD_RED
                }),
            ),
        ]));

        // Stats Footer Row
        text.push(Line::from(""));
        let rel_spans = vec![
            Span::styled("Stats   : ", Style::default().fg(theme::TEXT_SECONDARY)),
            Span::styled("PID ", Style::default().fg(theme::TEXT_SECONDARY)),
            Span::styled(
                details.pid.map_or("-".to_string(), |p| p.to_string()),
                Style::default().fg(theme::TEXT_PRIMARY),
            ),
            Span::styled(" | Drops ", Style::default().fg(theme::TEXT_SECONDARY)),
            Span::styled(
                format!("{}", app.connection_drops),
                Style::default().fg(if app.connection_drops > 0 {
                    theme::NORD_RED
                } else {
                    theme::TEXT_PRIMARY
                }),
            ),
        ];

        text.push(Line::from(rel_spans));

        frame.render_widget(Paragraph::new(text), inner);
    } else {
        let max_lines = inner.height as usize;
        let mut text: Vec<Line> = vec![
            Line::from(Span::styled(
                "Not Connected",
                Style::default()
                    .fg(theme::INACTIVE)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
        ];

        if let Some(idx) = app.profile_list_state.selected() {
            if let Some(profile) = app.profiles.get(idx) {
                text.push(Line::from(vec![
                    Span::styled("Profile : ", Style::default().fg(theme::TEXT_SECONDARY)),
                    Span::styled(&profile.name, Style::default().fg(theme::ACCENT_PRIMARY)),
                ]));
                text.push(Line::from(vec![
                    Span::styled("Protocol: ", Style::default().fg(theme::TEXT_SECONDARY)),
                    Span::styled(
                        profile.protocol.to_string(),
                        Style::default().fg(theme::TEXT_PRIMARY),
                    ),
                ]));
                text.push(Line::from(vec![
                    Span::styled("Config  : ", Style::default().fg(theme::TEXT_SECONDARY)),
                    Span::styled(
                        utils::truncate(
                            &profile.config_path.display().to_string(),
                            inner.width.saturating_sub(10) as usize,
                        ),
                        Style::default().fg(theme::TEXT_SECONDARY),
                    ),
                ]));
                if let Some(last_used) = profile.last_used {
                    text.push(Line::from(vec![
                        Span::styled("Last use: ", Style::default().fg(theme::TEXT_SECONDARY)),
                        Span::styled(
                            utils::format_relative_time(last_used),
                            Style::default().fg(theme::TEXT_PRIMARY),
                        ),
                    ]));
                }

                text.push(Line::from(""));

                // Pre-VPN network info
                if !app.public_ip.is_empty() {
                    text.push(Line::from(vec![
                        Span::styled("Your IP : ", Style::default().fg(theme::TEXT_SECONDARY)),
                        Span::styled(&app.public_ip, Style::default().fg(theme::WARNING)),
                    ]));
                }
                if !app.isp.is_empty()
                    && app.isp != "Unknown"
                    && app.isp != constants::MSG_DETECTING
                {
                    text.push(Line::from(vec![
                        Span::styled("ISP     : ", Style::default().fg(theme::TEXT_SECONDARY)),
                        Span::styled(&app.isp, Style::default().fg(theme::TEXT_PRIMARY)),
                    ]));
                }
                if !app.dns_server.is_empty() && app.dns_server != constants::MSG_DETECTING {
                    text.push(Line::from(vec![
                        Span::styled("DNS     : ", Style::default().fg(theme::TEXT_SECONDARY)),
                        Span::styled(&app.dns_server, Style::default().fg(theme::TEXT_PRIMARY)),
                    ]));
                }
            }
        } else {
            text.push(Line::from(vec![Span::styled(
                "Select a profile from the sidebar",
                Style::default().fg(theme::TEXT_SECONDARY),
            )]));
        }

        text.truncate(max_lines);
        frame.render_widget(Paragraph::new(text), inner);
    }
}

fn render_rename_overlay(frame: &mut Frame, name: &str, cursor: usize) {
    let area = frame.area();
    let width = 45u16.min(area.width.saturating_sub(4));
    let height = 5u16;
    let overlay = Rect {
        x: (area.width / 2).saturating_sub(width / 2),
        y: (area.height / 2).saturating_sub(height / 2),
        width,
        height,
    };

    frame.render_widget(Clear, overlay);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::ACCENT_PRIMARY))
        .title(Span::styled(
            " Rename Profile ",
            Style::default()
                .fg(theme::ACCENT_PRIMARY)
                .add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Span::styled(
            " Enter confirm │ Esc cancel ",
            Style::default().fg(Color::DarkGray),
        ));

    let inner = block.inner(overlay);
    frame.render_widget(block, overlay);

    let before: String = name.chars().take(cursor).collect();
    let after: String = name.chars().skip(cursor).collect();
    let mut spans = vec![
        Span::styled("> ", Style::default().fg(theme::ACCENT_PRIMARY)),
        Span::styled(before, Style::default().fg(theme::TEXT_PRIMARY)),
        Span::styled("▌", Style::default().fg(theme::ACCENT_PRIMARY)),
    ];
    if !after.is_empty() {
        spans.push(Span::styled(
            after,
            Style::default().fg(theme::TEXT_PRIMARY),
        ));
    }

    frame.render_widget(
        Paragraph::new(Line::from(spans)).alignment(Alignment::Left),
        inner,
    );
}

fn render_search_bar(frame: &mut Frame, app: &App, query: &str, cursor: usize, total: usize) {
    let area = frame.area();
    let bar_area = Rect {
        x: 1,
        y: area.height.saturating_sub(3),
        width: area.width.saturating_sub(2).min(60),
        height: 3,
    };

    frame.render_widget(Clear, bar_area);

    let match_count = app.search_match_count;

    let count_text = if query.is_empty() {
        format!("{total} profiles")
    } else if match_count == 0 {
        "no matches".to_string()
    } else {
        format!("{match_count} of {total}")
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::ACCENT_PRIMARY))
        .title(Span::styled(
            " Search ",
            Style::default()
                .fg(theme::ACCENT_PRIMARY)
                .add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Line::from(Span::styled(
            format!(" {count_text} "),
            Style::default().fg(Color::DarkGray),
        )));

    let inner = block.inner(bar_area);
    frame.render_widget(block, bar_area);

    let before: String = query.chars().take(cursor).collect();
    let after: String = query.chars().skip(cursor).collect();
    let mut spans = vec![
        Span::styled("/", Style::default().fg(theme::ACCENT_PRIMARY)),
        Span::styled(before, Style::default().fg(theme::TEXT_PRIMARY)),
        Span::styled("▌", Style::default().fg(theme::ACCENT_PRIMARY)),
    ];
    if !after.is_empty() {
        spans.push(Span::styled(
            after,
            Style::default().fg(theme::TEXT_PRIMARY),
        ));
    }

    if query.is_empty() {
        spans.push(Span::styled(
            "type to filter...",
            Style::default().fg(Color::DarkGray),
        ));
    }

    frame.render_widget(Paragraph::new(Line::from(spans)), inner);
}

fn render_confirm_switch(frame: &mut Frame, from: &str, to: &str, confirm: bool) {
    let area = frame.area();
    let width = 50u16.min(area.width.saturating_sub(4));
    let height = 7u16;
    let overlay = Rect {
        x: (area.width / 2).saturating_sub(width / 2),
        y: (area.height / 2).saturating_sub(height / 2),
        width,
        height,
    };

    frame.render_widget(Clear, overlay);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::WARNING))
        .title(Span::styled(
            " Switch Profile ",
            Style::default()
                .fg(theme::WARNING)
                .add_modifier(Modifier::BOLD),
        ));

    let inner = block.inner(overlay);
    frame.render_widget(block, overlay);

    let yes_style = if confirm {
        Style::default()
            .fg(Color::Black)
            .bg(theme::WARNING)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme::TEXT_SECONDARY)
    };
    let no_style = if confirm {
        Style::default().fg(theme::TEXT_SECONDARY)
    } else {
        Style::default()
            .fg(Color::Black)
            .bg(theme::ACCENT_PRIMARY)
            .add_modifier(Modifier::BOLD)
    };

    let text = vec![
        Line::from(vec![
            Span::styled(
                "Disconnect from ",
                Style::default().fg(theme::TEXT_SECONDARY),
            ),
            Span::styled(from, Style::default().fg(theme::ACCENT_PRIMARY)),
        ]),
        Line::from(vec![
            Span::styled(
                "and connect to ",
                Style::default().fg(theme::TEXT_SECONDARY),
            ),
            Span::styled(to, Style::default().fg(theme::SUCCESS)),
            Span::styled("?", Style::default().fg(theme::TEXT_SECONDARY)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("     ", Style::default()),
            Span::styled(if confirm { "▸ [Y]es " } else { "  [Y]es " }, yes_style),
            Span::styled("  ", Style::default()),
            Span::styled(if confirm { "  [N]o " } else { "▸ [N]o " }, no_style),
        ]),
    ];

    frame.render_widget(Paragraph::new(text), inner);
}
