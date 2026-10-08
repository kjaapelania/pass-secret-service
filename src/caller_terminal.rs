use log::debug;
use std::{collections::HashMap, path::Path};
use tokio::process::Command;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerTerminal {
    pub tty: String,
    pub term: Option<String>,
}

impl CallerTerminal {
    /// Attempt to discover the caller's terminal.
    ///
    /// Returns `Some(CallerTerminal)` only if:
    /// 1. Caller UID matches current user UID
    /// 2. Caller actually has a terminal (via GPG_TTY env var or stdin/stdout/stderr)
    ///
    /// Otherwise returns None so gpg runs as before without terminal attachment.
    pub fn from_caller(pid: u32, uid: u32) -> Option<Self> {
        let current_uid = unsafe { libc::getuid() };
        if uid != current_uid {
            debug!(
                "Caller UID {uid} does not match current UID {current_uid}; running gpg as before"
            );
            return None;
        }

        let mut env = get_process_environ(pid);
        let term = env.remove("TERM");
        let tty = env
            .remove("GPG_TTY")
            .filter(|p| is_terminal_path(Path::new(p)))
            .or_else(|| find_caller_fd_terminal(pid))?;

        debug!("Found caller terminal: {tty} (TERM: {term:?}) for PID {pid}");
        Some(CallerTerminal { tty, term })
    }

    /// Hands this terminal to the gpg command.
    pub fn apply_to_command(&self, command: &mut Command) {
        command.env("GPG_TTY", &self.tty);
        if let Some(term) = &self.term {
            command.env("TERM", term);
        }
    }
}

/// Checks whether a given path refers to an active terminal device.
/// Uses `stat(2)` metadata rather than `open(2)` to avoid driver side effects
/// on hardware serial ports.
pub fn is_terminal_path(path: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt;

    let path_str = path.to_string_lossy();

    // Must match standard pseudo-terminal (PTS) or virtual console naming.
    // Explicitly rejects /dev/tty itself (which refers to pinentry's own controlling
    // terminal rather than the caller's) and serial ports like ttyS* or ttyUSB*.
    let is_terminal_name = path_str.starts_with("/dev/pts/")
        || path_str
            .strip_prefix("/dev/tty")
            .is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()));

    if !is_terminal_name {
        return false;
    }

    // Inspect inode metadata (stat) without opening the device file
    std::fs::metadata(path)
        .map(|meta| meta.file_type().is_char_device())
        .unwrap_or(false)
}

/// Checks stdin (0), stdout (1), and stderr (2) of the given PID in order
/// and returns the path to the first one that is a terminal.
pub fn find_caller_fd_terminal(pid: u32) -> Option<String> {
    for fd in [0, 1, 2] {
        let proc_fd_path = format!("/proc/{pid}/fd/{fd}");
        if let Ok(target) = std::fs::read_link(&proc_fd_path) {
            if is_terminal_path(&target) {
                return Some(target.to_string_lossy().into_owned());
            }
        }
    }
    None
}

/// Parses null-delimited KEY=VALUE environment bytes from procfs into a HashMap.
pub fn parse_environ_bytes(bytes: &[u8]) -> HashMap<String, String> {
    let mut env = HashMap::new();
    for entry in bytes.split(|&b| b == 0) {
        if let Ok(s) = std::str::from_utf8(entry) {
            if let Some((k, v)) = s.split_once('=') {
                env.insert(k.to_string(), v.to_string());
            }
        }
    }
    env
}

/// Reads the environment of a process from `/proc/{pid}/environ`.
pub fn get_process_environ(pid: u32) -> HashMap<String, String> {
    let proc_path = format!("/proc/{pid}/environ");
    std::fs::read(proc_path)
        .map(|bytes| parse_environ_bytes(&bytes))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_different_uid_returns_none() {
        let current_uid = unsafe { libc::getuid() };
        let fake_uid = current_uid.wrapping_add(1000);
        let pid = std::process::id();
        assert_eq!(CallerTerminal::from_caller(pid, fake_uid), None);
    }

    #[test]
    fn test_is_terminal_path_validation() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        assert!(!is_terminal_path(temp.path()));
        assert!(!is_terminal_path(Path::new("/dev/null")));
        assert!(!is_terminal_path(Path::new("/nonexistent/path/for/sure")));
        assert!(!is_terminal_path(Path::new("/dev/tty"))); // Rejects /dev/tty itself
        assert!(!is_terminal_path(Path::new("/dev/ttyS0"))); // Rejects serial ports
        assert!(!is_terminal_path(Path::new("/dev/ttyUSB0"))); // Rejects serial ports
    }

    #[test]
    fn test_apply_to_command() {
        let caller = CallerTerminal {
            tty: "/dev/pts/42".to_string(),
            term: Some("xterm-256color".to_string()),
        };
        let mut cmd = Command::new("gpg");
        caller.apply_to_command(&mut cmd);

        let std_cmd = cmd.as_std();
        let envs: Vec<(String, Option<String>)> = std_cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|s| s.to_string_lossy().into_owned()),
                )
            })
            .collect();
        assert!(envs.contains(&("GPG_TTY".to_string(), Some("/dev/pts/42".to_string()))));
        assert!(envs.contains(&("TERM".to_string(), Some("xterm-256color".to_string()))));
    }

    #[test]
    fn test_apply_to_command_without_term() {
        let caller = CallerTerminal {
            tty: "/dev/pts/1".to_string(),
            term: None,
        };
        let mut cmd = Command::new("gpg");
        caller.apply_to_command(&mut cmd);

        let std_cmd = cmd.as_std();
        let envs: Vec<(String, Option<String>)> = std_cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|s| s.to_string_lossy().into_owned()),
                )
            })
            .collect();
        assert!(envs.contains(&("GPG_TTY".to_string(), Some("/dev/pts/1".to_string()))));
        assert!(!envs.iter().any(|(k, _)| k == "TERM"));
    }

    #[test]
    fn test_parse_environ_bytes() {
        let raw = b"GPG_TTY=/dev/pts/7\0TERM=alacritty\0HOME=/home/user\0EMPTY=\0INVALID_ENTRY\0";
        let env = parse_environ_bytes(raw);
        assert_eq!(env.get("GPG_TTY"), Some(&"/dev/pts/7".to_string()));
        assert_eq!(env.get("TERM"), Some(&"alacritty".to_string()));
        assert_eq!(env.get("HOME"), Some(&"/home/user".to_string()));
        assert_eq!(env.get("EMPTY"), Some(&"".to_string()));
        assert_eq!(env.get("INVALID_ENTRY"), None);
    }
}
