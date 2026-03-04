//! Help overlay showing all keybindings

use crate::theme;
use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame,
};

const HELP_TEXT: &[(&str, &[(&str, &str)])] = &[
    (
        "Global",
        &[
            ("1-9", "Quick connect to profile N"),
            ("d", "Disconnect / Cancel / Force Kill"),
            ("r", "Reconnect"),
            ("i", "Import profile (file, dir, URL)"),
            ("K", "Cycle kill switch mode"),
            ("y", "Copy VPN IP to clipboard"),
            ("Tab/S-Tab", "Next / Previous panel"),
            ("z", "Zoom focused panel"),
            ("x", "Action menu"),
            ("b", "Bulk action menu"),
            ("/", "Search profiles"),
            ("?", "Toggle this help"),
            ("q", "Quit"),
        ],
    ),
    (
        "Sidebar (Profiles)",
        &[
            ("j / ↓", "Next profile"),
            ("k / ↑", "Previous profile"),
            ("g / Home", "First profile"),
            ("G / End", "Last profile"),
            ("PgUp/PgDn", "Page up / down"),
            ("c / Enter", "Connect / disconnect"),
            ("R", "Rename profile"),
            ("v", "View config"),
            ("a", "Manage auth (OpenVPN)"),
            ("A", "Clear saved auth"),
            ("Del", "Delete profile"),
        ],
    ),
    (
        "Logs Panel",
        &[
            ("j / ↓", "Scroll down"),
            ("k / ↑", "Scroll up"),
            ("L", "Clear logs"),
        ],
    ),
    (
        "Config Viewer",
        &[
            ("j / ↓ / k / ↑", "Scroll"),
            ("g / G", "Top / Bottom"),
            ("Esc", "Close"),
        ],
    ),
];

pub fn render(frame: &mut Frame, scroll: u16) {
    let area = frame.area();
    let width = area.width.saturating_sub(4).min(65);
    let height = area.height.saturating_sub(2).min(38);
    if width == 0 || height == 0 {
        return;
    }

    let overlay = Rect {
        x: (area.width / 2).saturating_sub(width / 2),
        y: (area.height / 2).saturating_sub(height / 2),
        width,
        height,
    };

    frame.render_widget(Clear, overlay);

    let mut lines: Vec<Line> = Vec::new();

    for (section_idx, (section, bindings)) in HELP_TEXT.iter().enumerate() {
        if section_idx > 0 {
            lines.push(Line::from(""));
        }
        lines.push(Line::from(Span::styled(
            format!("  {section}"),
            Style::default()
                .fg(theme::ACCENT_PRIMARY)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        )));
        lines.push(Line::from(""));

        for (key, desc) in *bindings {
            lines.push(Line::from(vec![
                Span::styled(
                    format!("    {key:<14}"),
                    Style::default()
                        .fg(theme::KEY_HINT)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(*desc, Style::default().fg(theme::TEXT_SECONDARY)),
            ]));
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    let total_lines = lines.len() as u16;
    let inner_height = height.saturating_sub(2); // borders
    let max_scroll = total_lines.saturating_sub(inner_height);
    let clamped_scroll = scroll.min(max_scroll);

    let can_scroll_down = clamped_scroll < max_scroll;
    let can_scroll_up = clamped_scroll > 0;
    let scroll_hint = match (can_scroll_up, can_scroll_down) {
        (true, true) => " ↑↓ scroll · ? close ",
        (false, true) => " ↓ scroll · ? close ",
        (true, false) => " ↑ scroll · ? close ",
        (false, false) => " ? or Esc to close ",
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::ACCENT_PRIMARY))
        .title(Span::styled(
            " Keybindings ",
            Style::default()
                .fg(theme::ACCENT_PRIMARY)
                .add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Span::styled(
            scroll_hint,
            Style::default().fg(theme::KEY_HINT_DESC),
        ));

    let inner = block.inner(overlay);
    frame.render_widget(block, overlay);

    let paragraph = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .scroll((clamped_scroll, 0));
    frame.render_widget(paragraph, inner);
}
