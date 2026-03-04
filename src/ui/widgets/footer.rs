//! Footer widget with context-aware keybinding hints

use crate::app::{App, ConnectionState};
use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

/// Render dashboard footer with context-aware shortcuts
pub fn render_dashboard(frame: &mut Frame, app: &App, area: Rect) {
    // Config overlay takes priority
    if app.show_config {
        let hints = vec![
            ("↑↓", "Scroll"),
            ("g", "Top"),
            ("G", "End"),
            ("Esc", "Close"),
        ];
        render_hints(frame, area, &hints, None);
        return;
    }

    // Determine focused panel name for display
    let panel_name = match &app.focused_panel {
        crate::app::FocusedPanel::Sidebar => "Profiles",
        crate::app::FocusedPanel::ConnectionDetails => "Details",
        crate::app::FocusedPanel::Chart => "Chart",
        crate::app::FocusedPanel::Security => "Security",
        crate::app::FocusedPanel::Logs => "Logs",
    };

    let mut hints = Vec::new();

    match &app.focused_panel {
        crate::app::FocusedPanel::Sidebar => {
            hints.extend_from_slice(&[
                ("j/k", "Navigate"),
                ("c", "Connect"),
                ("v", "View Config"),
                ("R", "Rename"),
                ("i", "Import"),
                ("DEL", "Delete"),
            ]);
        }
        crate::app::FocusedPanel::Logs => {
            hints.extend_from_slice(&[
                ("j/k", "Scroll"),
                ("g/G", "Top/End"),
                ("f", "Filter"),
                ("L", "Clear"),
            ]);
        }
        crate::app::FocusedPanel::Chart
        | crate::app::FocusedPanel::Security
        | crate::app::FocusedPanel::ConnectionDetails => {
            hints.push(("z", "Zoom"));
        }
    }

    let disconnect_hint = match &app.connection_state {
        ConnectionState::Connecting { .. } => ("d", "Cancel"),
        ConnectionState::Disconnecting { .. } => ("d", "Force Kill"),
        ConnectionState::Connected { .. } => ("d", "Disconnect"),
        ConnectionState::Disconnected => {
            if app.last_connected_profile.is_some() {
                ("r", "Reconnect")
            } else {
                ("", "")
            }
        }
    };
    if !disconnect_hint.0.is_empty() {
        hints.push(disconnect_hint);
    }

    hints.extend_from_slice(&[
        ("Tab", "Panel"),
        ("K", "KillSw"),
        ("?", "Help"),
        ("q", "Quit"),
    ]);

    render_hints(frame, area, &hints, Some(panel_name));
}

fn render_hints(frame: &mut Frame, area: Rect, hints: &[(&str, &str)], panel_name: Option<&str>) {
    use ratatui::layout::{Constraint, Layout};

    let chunks = Layout::default()
        .direction(ratatui::layout::Direction::Horizontal)
        .constraints([
            Constraint::Min(0),     // Hints (left)
            Constraint::Length(16), // Branding (right)
        ])
        .split(area);

    // 1. Render hints on the left with optional panel indicator
    let mut hint_spans = Vec::new();
    let mut current_width = 0;
    let max_width = chunks[0].width as usize;

    if let Some(panel) = panel_name {
        let panel_indicator = format!("[{panel}] ");
        hint_spans.push(Span::styled(
            panel_indicator.clone(),
            Style::default()
                .fg(crate::theme::KEY_HINT)
                .add_modifier(Modifier::BOLD),
        ));
        current_width += panel_indicator.len();
    } else {
        hint_spans.push(Span::raw(" "));
        current_width += 1;
    }

    for (i, (key, action)) in hints.iter().enumerate() {
        let sep_width = if i > 0 { 3 } else { 0 };
        let item_width = key.len() + 1 + action.len() + sep_width;

        if current_width + item_width > max_width {
            break;
        }

        if i > 0 {
            hint_spans.push(Span::styled(
                " │ ",
                Style::default().fg(crate::theme::SEPARATOR),
            ));
        }
        hint_spans.push(Span::styled(
            *key,
            Style::default()
                .fg(crate::theme::KEY_HINT)
                .add_modifier(Modifier::BOLD),
        ));
        hint_spans.push(Span::raw(" "));
        hint_spans.push(Span::styled(
            *action,
            Style::default().fg(crate::theme::KEY_HINT_DESC),
        ));

        current_width += item_width;
    }
    frame.render_widget(Paragraph::new(Line::from(hint_spans)), chunks[0]);

    // 2. Render branding on the right
    let branding = Line::from(vec![Span::styled(
        format!(
            "{} v{} ",
            crate::constants::APP_NAME,
            crate::constants::APP_VERSION
        ),
        Style::default().fg(crate::theme::NORD_POLAR_NIGHT_4),
    )]);
    frame.render_widget(
        Paragraph::new(branding).alignment(ratatui::layout::Alignment::Right),
        chunks[1],
    );
}
