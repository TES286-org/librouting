//! Shared named-pipe path normalization.
//!
//! Used by the Windows runtime-API server (`api_imp_windows.rs`) and
//! the `lrctl` Windows client transport so the two ends always agree on
//! the pipe name. Lives in its own module (rather than `api.rs`) so the
//! `lrctl` binary — a separate crate root with no `mod api;` — can pull
//! in just this helper without dragging in the server-side
//! `serve_connection` machinery.

/// Normalize a socket path to a Windows named-pipe path.
///
/// On Windows the runtime API rides a named pipe (`\\.\pipe\<name>`)
/// rather than a Unix domain socket. The operator configures the path
/// through `api_socket` / `--api-socket` using the same string on every
/// platform — `templates/daemon.toml` ships the Unix-style default
/// `/run/lr-daemon.api`. This helper maps that string to a valid pipe
/// name so the default works on Windows without a per-platform config.
///
/// - A path that already starts with `\\.\pipe\` (case-insensitive) is
///   returned verbatim — the operator wrote an explicit pipe name and
///   the two ends must agree on it byte for byte.
/// - Any other path is split on `/` and `\` and the last non-empty
///   component is taken as the pipe name, then prefixed with
///   `\\.\pipe\`. This turns `/run/lr-daemon.api`,
///   `C:\Users\me\lr.api` and the bare `lr-daemon.api` all into
///   `\\.\pipe\lr-daemon.api`.
///
/// Compiles on every platform so the unit tests run on Linux CI too.
/// On non-Windows production builds the function is unreferenced (the
/// two callers — the Windows server and the Windows `lrctl` client —
/// are both `cfg(windows)`); `allow(dead_code)` keeps the warning
/// quiet without gating the function away from the test build.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn normalize_pipe_name(path: &str) -> String {
    const PREFIX: &str = r"\\.\pipe\";
    if path.to_ascii_lowercase().starts_with(PREFIX) {
        return path.to_string();
    }
    let name = path
        .rsplit(['/', '\\'])
        .find(|s| !s.is_empty())
        .unwrap_or("");
    format!("{PREFIX}{name}")
}

#[cfg(test)]
mod tests {
    use super::normalize_pipe_name;

    #[test]
    fn explicit_pipe_name_passes_through() {
        assert_eq!(
            normalize_pipe_name(r"\\.\pipe\lr-daemon"),
            r"\\.\pipe\lr-daemon"
        );
        // Case-insensitive prefix match — the rest is preserved verbatim.
        assert_eq!(
            normalize_pipe_name(r"\\.\PIPE\Lr-Daemon"),
            r"\\.\PIPE\Lr-Daemon"
        );
    }

    #[test]
    fn unix_style_path_becomes_pipe_name() {
        assert_eq!(
            normalize_pipe_name("/run/lr-daemon.api"),
            r"\\.\pipe\lr-daemon.api"
        );
        // Deep paths collapse to the last component — Windows pipe
        // names are flat, not hierarchical.
        assert_eq!(
            normalize_pipe_name("/var/run/lr/api.sock"),
            r"\\.\pipe\api.sock"
        );
    }

    #[test]
    fn windows_path_becomes_pipe_name() {
        assert_eq!(
            normalize_pipe_name(r"C:\Users\me\lr-daemon.api"),
            r"\\.\pipe\lr-daemon.api"
        );
        // Both separators are recognized so a mixed-separator path
        // still extracts the right component.
        assert_eq!(
            normalize_pipe_name(r"C:\Users/me\lr.api"),
            r"\\.\pipe\lr.api"
        );
    }

    #[test]
    fn bare_name_becomes_pipe_name() {
        assert_eq!(
            normalize_pipe_name("lr-daemon.api"),
            r"\\.\pipe\lr-daemon.api"
        );
        // A trailing separator yields the same pipe name as the bare
        // form — the empty trailing component is skipped.
        assert_eq!(
            normalize_pipe_name("/run/lr-daemon.api/"),
            r"\\.\pipe\lr-daemon.api"
        );
    }

    #[test]
    fn empty_path_yields_bare_prefix() {
        // An empty path normalizes to just the prefix; the subsequent
        // CreateNamedPipeW / CreateFileW call fails with a clear
        // ERROR_INVALID_NAME rather than panicking here.
        assert_eq!(normalize_pipe_name(""), r"\\.\pipe\");
    }
}
