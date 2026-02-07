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

impl Toast {
    /// Check if the toast notification has expired
    pub fn is_expired(&self) -> bool {
        Instant::now() > self.expires
    }
}
