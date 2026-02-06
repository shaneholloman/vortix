//! CLI command handlers.

use crate::cli::args::Commands;
use color_eyre::Result;
use std::path::Path;

/// Handles CLI commands that don't require the TUI.
///
/// Returns `true` if the command was handled and the program should exit,
/// or `false` if the TUI should be started.
#[allow(clippy::unnecessary_wraps)]
pub fn handle_command(command: &Commands) -> Result<bool> {
    match command {
        Commands::Import { file } => {
            handle_import(file);
            Ok(true)
        }
        Commands::Update => {
            handle_update();
            Ok(true)
        }
        Commands::ReleaseKillSwitch => {
            handle_release_killswitch();
            Ok(true)
        }
    }
}

use crate::constants;

/// Imports a VPN profile from the specified file path or directory.
fn handle_import(file: &str) {
    use crate::core::importer::{resolve_target, ImportTarget};

    match resolve_target(file) {
        Ok(ImportTarget::Url(url)) => {
            println!("{}", constants::CLI_MSG_DOWNLOADING);
            match crate::core::downloader::download_profile(&url) {
                Ok(downloaded_path) => {
                    // The downloaded path is a temp file
                    import_single_file(&downloaded_path);
                }
                Err(e) => {
                    eprintln!("{}{}", constants::CLI_MSG_IMPORT_FAILED, e);
                    std::process::exit(1);
                }
            }
        }
        Ok(ImportTarget::File(path)) => {
            import_single_file(&path);
        }
        Ok(ImportTarget::Directory(path)) => {
            import_from_directory(&path);
        }
        Err(e) => {
            eprintln!("{}{}", constants::CLI_MSG_ERROR, e);
            std::process::exit(1);
        }
    }
}

/// Import a single VPN profile file
fn import_single_file(path: &Path) {
    match crate::vpn::import_profile(path) {
        Ok(profile) => {
            println!("{}{}", constants::CLI_MSG_IMPORT_SUCCESS, profile.name);
            println!(
                "{}{}",
                constants::CLI_MSG_IMPORT_DETAILS_PROTO,
                profile.protocol
            );
            println!(
                "{}{}",
                constants::CLI_MSG_IMPORT_DETAILS_LOC,
                profile.location
            );
            println!(
                "{}{}",
                constants::CLI_MSG_IMPORT_DETAILS_PATH,
                profile.config_path.display()
            );
        }
        Err(e) => {
            eprintln!("{}{}", constants::CLI_MSG_IMPORT_FAILED, e);
            std::process::exit(1);
        }
    }
}

/// Bulk import all .conf and .ovpn files from a directory
fn import_from_directory(dir_path: &Path) {
    let mut imported = 0;
    let mut failed = 0;

    match std::fs::read_dir(dir_path) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let path = entry.path();

                if path.is_file()
                    && path
                        .extension()
                        .is_some_and(|ext| ext == "conf" || ext == "ovpn")
                {
                    match crate::vpn::import_profile(&path) {
                        Ok(profile) => {
                            println!("  ✅ {}", profile.name); // Keeping checkmark list item simple
                            imported += 1;
                        }
                        Err(e) => {
                            eprintln!("  ❌ {} - {}", path.display(), e);
                            failed += 1;
                        }
                    }
                }
            }

            // Show summary
            println!("{}", constants::CLI_MSG_SUMMARY_HEADER);
            println!("{}{}", constants::CLI_MSG_SUMMARY_IMPORTED, imported);
            if failed > 0 {
                println!("{}{}", constants::CLI_MSG_SUMMARY_FAILED, failed);
            }

            if imported == 0 {
                eprintln!("{}", constants::CLI_MSG_NO_FILES);
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("{}{}", constants::CLI_MSG_DIR_ERROR, e);
            std::process::exit(1);
        }
    }
}

/// Handles the update command by running cargo install.
fn handle_update() {
    println!("{}", constants::CLI_MSG_UPDATE_START);

    let status = std::process::Command::new("cargo")
        .args(["install", "vortix", "--force"])
        .status();

    match status {
        Ok(s) if s.success() => {
            println!("{}", constants::CLI_MSG_UPDATE_SUCCESS);
            println!("{}", constants::CLI_MSG_UPDATE_CHECK);
        }
        Ok(_) => {
            eprintln!("{}", constants::CLI_MSG_UPDATE_FAIL_MANUAL);
            eprintln!("{}", constants::CLI_MSG_UPDATE_CMD);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("{}{}", constants::CLI_MSG_UPDATE_FAIL_CARGO, e);
            eprintln!("{}", constants::CLI_MSG_UPDATE_PATH_HINT);
            std::process::exit(1);
        }
    }
}

/// Handles the release-killswitch command.
/// Emergency release of kill switch firewall rules.
fn handle_release_killswitch() {
    println!("Releasing kill switch...");

    // Attempt to disable blocking
    match crate::core::killswitch::disable_blocking() {
        Ok(()) => {
            println!("Kill switch firewall rules flushed.");
        }
        Err(e) => {
            eprintln!("Warning: Failed to flush firewall rules: {e}");
            eprintln!("{}", crate::platform::KILLSWITCH_EMERGENCY_MSG);
        }
    }

    // Clear persisted state
    crate::core::killswitch::clear_state();
    println!("Kill switch state cleared.");
    println!("Internet access should be restored.");
}
