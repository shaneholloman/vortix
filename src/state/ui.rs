//! UI state types.

use super::Protocol;
use std::time::{Duration, Instant};

/// Duration for toast notifications to remain visible.
pub const DISMISS_DURATION: Duration = Duration::from_secs(4);

/// Currently focused UI panel for keyboard navigation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub enum FocusedPanel {
    /// VPN profiles sidebar.
    #[default]
    Sidebar,
    /// Connection details panel (bottom left).
    ConnectionDetails,
    /// Throughput chart (top right).
    Chart,
    /// Security guard panel (bottom right -> left).
    Security,
    /// Activity log panel (bottom right -> right).
    Logs,
}

/// Which field is focused in the auth credentials overlay.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AuthField {
    /// Username text input.
    Username,
    /// Password text input (masked).
    Password,
    /// "Save credentials" checkbox.
    SaveCheckbox,
}

/// Current input mode determining keyboard behavior.
#[derive(Clone, Debug, PartialEq, Default)]
pub enum InputMode {
    /// Normal navigation mode.
    #[default]
    Normal,
    /// File path import dialog is active.
    Import {
        /// Current input path string.
        path: String,
        /// Current cursor position in the path string.
        cursor: usize,
    },
    /// Dependency error dialog showing missing tools.
    DependencyError {
        /// Protocol that requires the missing dependencies.
        protocol: Protocol,
        /// List of missing tool names.
        missing: Vec<String>,
    },
    /// Permission denied error dialog.
    PermissionDenied {
        /// Description of the action that was denied.
        action: String,
    },
    /// Delete confirmation dialog.
    ConfirmDelete {
        /// Index of the profile to delete.
        index: usize,
        /// Name of the profile to delete.
        name: String,
        /// Is "Yes" selected?
        confirm_selected: bool,
    },
    /// Help overlay showing all keybindings.
    Help {
        /// Vertical scroll offset.
        scroll: u16,
    },
    /// Profile rename dialog.
    Rename {
        /// Index of the profile being renamed.
        index: usize,
        /// New name being typed.
        new_name: String,
        /// Cursor position.
        cursor: usize,
    },
    /// Profile search/filter mode.
    Search {
        /// Current search query string.
        query: String,
        /// Cursor position in the query.
        cursor: usize,
    },
    /// Confirmation dialog for switching VPN profile while connected.
    ConfirmSwitch {
        from: String,
        to_idx: usize,
        to_name: String,
        confirm_selected: bool,
    },
    /// Confirmation dialog before quitting while VPN is connected.
    ConfirmQuit {
        /// Is "Yes" currently selected?
        confirm_selected: bool,
    },
    /// `OpenVPN` authentication credentials dialog.
    AuthPrompt {
        /// Index of the profile requiring auth.
        profile_idx: usize,
        /// Name of the profile (for display).
        profile_name: String,
        /// Username input.
        username: String,
        /// Cursor position in the username field.
        username_cursor: usize,
        /// Password input.
        password: String,
        /// Cursor position in the password field.
        password_cursor: usize,
        /// Which field is currently focused.
        focused_field: AuthField,
        /// Whether to persist credentials for future sessions.
        save_credentials: bool,
        /// Whether to auto-connect after submitting (false = save-only mode).
        connect_after: bool,
    },
}

/// Profile list sort ordering.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ProfileSortOrder {
    /// Alphabetical A → Z (default).
    #[default]
    NameAsc,
    /// Alphabetical Z → A.
    NameDesc,
    /// Most recently used first.
    LastUsed,
    /// Group by protocol (`WireGuard` first, then `OpenVPN`).
    Protocol,
}

impl ProfileSortOrder {
    /// Cycle to the next sort order.
    #[must_use]
    pub fn next(self) -> Self {
        match self {
            Self::NameAsc => Self::NameDesc,
            Self::NameDesc => Self::LastUsed,
            Self::LastUsed => Self::Protocol,
            Self::Protocol => Self::NameAsc,
        }
    }

    /// Short label for display in the sidebar title.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NameAsc => "A→Z",
            Self::NameDesc => "Z→A",
            Self::LastUsed => "Recent",
            Self::Protocol => "Proto",
        }
    }
}

/// Types of toast notifications for color coding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ToastType {
    /// Informational message (Blue)
    #[default]
    Info,
    /// Success message (Green)
    Success,
    /// Warning message (Yellow)
    Warning,
    /// Error message (Red)
    Error,
}

/// Toast notification for temporary messages.
#[derive(Clone)]
pub struct Toast {
    /// Message to display.
    pub message: String,
    /// Type of toast for styling.
    #[allow(clippy::struct_field_names)]
    pub toast_type: ToastType,
    /// When the toast should disappear.
    pub expires: Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum QualityLevel {
    #[default]
    Unknown,
    Excellent,
    Fair,
    Poor,
}

impl QualityLevel {
    #[must_use]
    pub fn from_metrics(latency_ms: u64, packet_loss: f32, jitter_ms: u64) -> Self {
        if latency_ms == 0 && packet_loss == 0.0 && jitter_ms == 0 {
            return Self::Unknown;
        }
        if packet_loss >= 5.0 || jitter_ms >= 15 || latency_ms >= 300 {
            Self::Poor
        } else if packet_loss >= 1.0 || jitter_ms >= 5 || latency_ms >= 100 {
            Self::Fair
        } else {
            Self::Excellent
        }
    }
}

impl Toast {
    /// Check if the toast notification has expired
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Instant::now() > self.expires
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quality_unknown_when_all_zero() {
        assert_eq!(QualityLevel::from_metrics(0, 0.0, 0), QualityLevel::Unknown);
    }

    #[test]
    fn quality_excellent_low_metrics() {
        assert_eq!(
            QualityLevel::from_metrics(30, 0.0, 2),
            QualityLevel::Excellent
        );
    }

    #[test]
    fn quality_fair_moderate_latency() {
        assert_eq!(QualityLevel::from_metrics(150, 0.0, 0), QualityLevel::Fair);
    }

    #[test]
    fn quality_poor_high_latency() {
        assert_eq!(QualityLevel::from_metrics(400, 0.0, 0), QualityLevel::Poor);
    }

    #[test]
    fn quality_poor_high_packet_loss() {
        assert_eq!(QualityLevel::from_metrics(20, 6.0, 1), QualityLevel::Poor);
    }

    #[test]
    fn quality_fair_moderate_jitter() {
        assert_eq!(QualityLevel::from_metrics(20, 0.0, 8), QualityLevel::Fair);
    }
}
