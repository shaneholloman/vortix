use crate::app::App;
use crate::{constants, logger, theme, utils};
use ratatui::{
    layout::{Alignment, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState},
    Frame,
};

#[allow(clippy::too_many_lines)]
pub(super) fn render(frame: &mut Frame, app: &mut App, area: Rect) {
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

    let visible_lines = inner.height as usize;
    let panel_width = inner.width as usize;
    let max_msg_len = panel_width.saturating_sub(constants::LOG_PREFIX_WIDTH);

    let mut lines: Vec<Line> = Vec::new();

    for entry in &all_logs {
        let time_str = utils::format_system_time_local(entry.timestamp);
        let level_tag = entry.level.prefix();

        let cat = format!(
            "{:<width$}",
            entry.category,
            width = constants::LOG_CATEGORY_WIDTH
        );

        let level_style = match entry.level {
            logger::LogLevel::Error => Style::default().fg(theme::ERROR),
            logger::LogLevel::Warning => Style::default().fg(theme::WARNING),
            logger::LogLevel::Info => Style::default().fg(theme::NORD_FROST_3),
            logger::LogLevel::Debug => Style::default().fg(Color::DarkGray),
        };

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

        let chunks = soft_wrap(&entry.message, max_msg_len);

        // First line: full prefix + first chunk of message
        lines.push(Line::from(vec![
            Span::styled(
                format!("[{time_str}] "),
                Style::default().fg(theme::TEXT_SECONDARY),
            ),
            Span::styled(format!("{level_tag} "), level_style),
            Span::styled(
                format!("{cat}  "),
                Style::default().fg(theme::NORD_POLAR_NIGHT_4),
            ),
            Span::styled(chunks[0].to_string(), msg_style),
        ]));

        // Continuation lines: indented to align with message column
        for chunk in &chunks[1..] {
            lines.push(Line::from(vec![
                Span::raw(" ".repeat(constants::LOG_PREFIX_WIDTH)),
                Span::styled((*chunk).to_string(), msg_style),
            ]));
        }
    }

    let total_visual_lines = lines.len();
    let max_scroll = total_visual_lines.saturating_sub(visible_lines);
    app.logs_max_scroll = u16::try_from(max_scroll).unwrap_or(u16::MAX);

    let scroll_pos = if app.logs_auto_scroll {
        max_scroll
    } else {
        (app.logs_scroll as usize).min(max_scroll)
    };

    let end = (scroll_pos + visible_lines).min(total_visual_lines);
    let visible_slice = &lines[scroll_pos..end];

    frame.render_widget(Paragraph::new(visible_slice.to_vec()), inner);

    // Scrollbar
    let scrollbar = Scrollbar::default()
        .orientation(ScrollbarOrientation::VerticalRight)
        .begin_symbol(Some("↑"))
        .end_symbol(Some("↓"))
        .style(Style::default().fg(theme::NORD_POLAR_NIGHT_4))
        .thumb_style(Style::default().fg(theme::ACCENT_PRIMARY));

    let mut scrollbar_state = ScrollbarState::new(max_scroll).position(scroll_pos);

    frame.render_stateful_widget(
        scrollbar,
        area.inner(ratatui::layout::Margin {
            vertical: 1,
            horizontal: 0,
        }),
        &mut scrollbar_state,
    );
}

/// Split `text` into chunks that each fit within `max_width` columns.
/// Prefers breaking at word boundaries (spaces) for readability.
fn soft_wrap(text: &str, max_width: usize) -> Vec<&str> {
    if max_width == 0 {
        return vec![text];
    }
    if text.len() <= max_width {
        return vec![text];
    }

    let mut chunks = Vec::new();
    let mut start = 0;

    while start < text.len() {
        if text.len() - start <= max_width {
            chunks.push(&text[start..]);
            break;
        }

        let mut end = start + max_width;
        // Retreat to a char boundary
        while end > start && !text.is_char_boundary(end) {
            end -= 1;
        }

        // Try to break at a space within the last 30% for readability
        let search_from = start + (max_width * 7 / 10);
        if let Some(space_pos) = text[search_from..end].rfind(' ') {
            end = search_from + space_pos + 1; // include the space on this line
        }

        chunks.push(&text[start..end]);
        start = end;
    }

    if chunks.is_empty() {
        chunks.push(text);
    }
    chunks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soft_wrap_short_message() {
        let chunks = soft_wrap("hello world", 80);
        assert_eq!(chunks, vec!["hello world"]);
    }

    #[test]
    fn soft_wrap_breaks_at_space() {
        let chunks = soft_wrap("the quick brown fox jumps", 15);
        assert_eq!(chunks[0].len(), 15);
        assert!(chunks[0].ends_with(' ') || chunks[0].len() <= 15);
        let rejoined: String = chunks.join("");
        assert_eq!(rejoined, "the quick brown fox jumps");
    }

    #[test]
    fn soft_wrap_long_word() {
        let long = "a".repeat(100);
        let chunks = soft_wrap(&long, 30);
        assert!(chunks.len() >= 4);
        let rejoined: String = chunks.join("");
        assert_eq!(rejoined, long);
    }

    #[test]
    fn soft_wrap_preserves_content() {
        let msg = "OpenVPN: Options error: --cert fails with 'client.crt': No such file";
        let chunks = soft_wrap(msg, 25);
        let rejoined: String = chunks.join("");
        assert_eq!(rejoined, msg);
    }

    #[test]
    fn soft_wrap_zero_width() {
        let chunks = soft_wrap("test", 0);
        assert_eq!(chunks, vec!["test"]);
    }
}
