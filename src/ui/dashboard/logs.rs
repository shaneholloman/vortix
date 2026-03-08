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
pub(super) fn render(frame: &mut Frame, app: &App, area: Rect) {
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
