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
                "Caller UID {} does not match current UID {}; running gpg as before",
                uid, current_uid
            );
            return None;
        }

        let env = get_process_environ(pid);
        let gpg_tty_env = env.get("GPG_TTY").filter(|s| !s.trim().is_empty()).cloned();
        let term = env.get("TERM").filter(|s| !s.trim().is_empty()).cloned();

        let terminal = resolve_terminal_with(
            gpg_tty_env,
            |tty| is_terminal_path(Path::new(tty)),
            || find_caller_fd_terminal(pid),
        );

        match terminal {
            Some(tty) => {
                debug!(
                    "Found caller terminal: {} (TERM: {:?}) for PID {}",
                    tty, term, pid
                );
                Some(CallerTerminal { tty, term })
            }
            None => {
                debug!("Caller PID {} has no terminal; running gpg as before", pid);
                None
            }
        }
    }

    /// Hands this terminal to the gpg command.
    pub fn apply_to_command(&self, command: &mut Command) {
        command.env("GPG_TTY", &self.tty);
        command.arg("--ttyname").arg(&self.tty);
        if let Some(term) = &self.term {
            command.env("TERM", term);
            command.arg("--ttytype").arg(term);
        }
    }
}

/// Resolves the terminal path according to the precedence rules:
/// 1. If GPG_TTY is set in the environment and refers to a terminal, use it.
/// 2. Otherwise, fall back to checking the caller's file descriptors.
pub fn resolve_terminal_with<F, G>(
    gpg_tty_env: Option<String>,
    is_terminal: F,
    find_fd_terminal: G,
) -> Option<String>
where
    F: Fn(&str) -> bool,
    G: FnOnce() -> Option<String>,
{
    if let Some(gpg_tty) = gpg_tty_env {
        if is_terminal(&gpg_tty) {
            Some(gpg_tty)
        } else {
            debug!(
                "Caller GPG_TTY ({}) is not a valid terminal; falling back to stdin/stdout/stderr",
                gpg_tty
            );
            find_fd_terminal()
        }
    } else {
        find_fd_terminal()
    }
}

/// Checks whether a given path refers to an active terminal device.
pub fn is_terminal_path(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;

    let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };

    let mut fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY,
        )
    };
    if fd < 0 {
        fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_WRONLY | libc::O_NONBLOCK | libc::O_NOCTTY,
            )
        };
    }

    if fd >= 0 {
        let is_tty = unsafe { libc::isatty(fd) } == 1;
        unsafe { libc::close(fd) };
        is_tty
    } else {
        false
    }
}

/// Helper that checks fds 0, 1, 2 in order and returns the first terminal found.
pub fn find_fd_terminal_with<F>(mut check_fd: F) -> Option<String>
where
    F: FnMut(i32) -> Option<String>,
{
    for fd in [0, 1, 2] {
        if let Some(term) = check_fd(fd) {
            return Some(term);
        }
    }
    None
}

/// Checks stdin (0), stdout (1), and stderr (2) of the given PID in order
/// and returns the path to the first one that is a terminal.
pub fn find_caller_fd_terminal(pid: u32) -> Option<String> {
    find_fd_terminal_with(|fd| {
        let proc_fd_path_str = format!("/proc/{pid}/fd/{fd}");
        let proc_fd_path = Path::new(&proc_fd_path_str);

        if let Ok(target) = std::fs::read_link(proc_fd_path) {
            if is_terminal_path(&target) || is_terminal_path(proc_fd_path) {
                return Some(target.to_string_lossy().into_owned());
            }
        } else if is_terminal_path(proc_fd_path) {
            return Some(proc_fd_path_str);
        }
        None
    })
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
    if let Ok(bytes) = std::fs::read(&proc_path) {
        parse_environ_bytes(&bytes)
    } else {
        HashMap::new()
    }
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
    fn test_is_terminal_path_non_terminal() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        assert!(!is_terminal_path(temp.path()));
        assert!(!is_terminal_path(Path::new("/dev/null")));
        assert!(!is_terminal_path(Path::new("/nonexistent/path/for/sure")));
    }

    #[test]
    fn test_apply_to_command() {
        let caller = CallerTerminal {
            tty: "/dev/pts/42".to_string(),
            term: Some("xterm-256color".to_string()),
        };
        let mut cmd = Command::new("gpg");
        caller.apply_to_command(&mut cmd);

        // Verify command has been configured
        let std_cmd = cmd.as_std();
        let args: Vec<String> = std_cmd
            .get_args()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert!(args.contains(&"--ttyname".to_string()));
        assert!(args.contains(&"/dev/pts/42".to_string()));
        assert!(args.contains(&"--ttytype".to_string()));
        assert!(args.contains(&"xterm-256color".to_string()));

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
        let args: Vec<String> = std_cmd
            .get_args()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert!(args.contains(&"--ttyname".to_string()));
        assert!(!args.contains(&"--ttytype".to_string()));

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

    #[test]
    fn test_resolve_terminal_with_valid_gpg_tty() {
        let resolved = resolve_terminal_with(
            Some("/dev/pts/2".to_string()),
            |path| path == "/dev/pts/2",
            || panic!("Should not check fds when GPG_TTY is valid"),
        );
        assert_eq!(resolved, Some("/dev/pts/2".to_string()));
    }

    #[test]
    fn test_resolve_terminal_with_invalid_gpg_tty_falls_back() {
        let resolved = resolve_terminal_with(
            Some("/dev/stale_pts".to_string()),
            |_path| false, // Not a terminal
            || Some("/dev/pts/fallback".to_string()),
        );
        assert_eq!(resolved, Some("/dev/pts/fallback".to_string()));
    }

    #[test]
    fn test_resolve_terminal_without_gpg_tty_uses_fallback() {
        let resolved = resolve_terminal_with(
            None,
            |_path| true,
            || Some("/dev/pts/from_stdin".to_string()),
        );
        assert_eq!(resolved, Some("/dev/pts/from_stdin".to_string()));
    }

    #[test]
    fn test_resolve_terminal_no_terminal_anywhere() {
        let resolved = resolve_terminal_with(None, |_path| false, || None);
        assert_eq!(resolved, None);
    }

    #[test]
    fn test_find_fd_terminal_order() {
        // 1. Stdin (0) is terminal: returns stdin, doesn't evaluate stdout or stderr
        let mut checked = Vec::new();
        let res = find_fd_terminal_with(|fd| {
            checked.push(fd);
            if fd == 0 {
                Some("/dev/pts/stdin".to_string())
            } else {
                Some("/dev/pts/other".to_string())
            }
        });
        assert_eq!(res, Some("/dev/pts/stdin".to_string()));
        assert_eq!(checked, vec![0]);

        // 2. Stdin (0) is redirected, stdout (1) is terminal
        checked.clear();
        let res = find_fd_terminal_with(|fd| {
            checked.push(fd);
            if fd == 1 {
                Some("/dev/pts/stdout".to_string())
            } else {
                None
            }
        });
        assert_eq!(res, Some("/dev/pts/stdout".to_string()));
        assert_eq!(checked, vec![0, 1]);

        // 3. Stdin (0) and stdout (1) are redirected, stderr (2) is terminal
        checked.clear();
        let res = find_fd_terminal_with(|fd| {
            checked.push(fd);
            if fd == 2 {
                Some("/dev/pts/stderr".to_string())
            } else {
                None
            }
        });
        assert_eq!(res, Some("/dev/pts/stderr".to_string()));
        assert_eq!(checked, vec![0, 1, 2]);

        // 4. None of 0, 1, 2 are terminals
        checked.clear();
        let res = find_fd_terminal_with(|fd| {
            checked.push(fd);
            None
        });
        assert_eq!(res, None);
        assert_eq!(checked, vec![0, 1, 2]);
    }
}
