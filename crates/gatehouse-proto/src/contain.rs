//! Path containment checks for policy matching.
//!
//! Two questions get asked of a path and a root directory:
//!
//! - **strict** ("is this certainly inside?") gates *permissive* decisions —
//!   the workspace auto-allow and `allow`-tier `path_prefix` rules. The path
//!   must be absolute, must be inside the root after lexical normalisation
//!   (`.`/`..` resolved without touching the filesystem, prefix compared
//!   component-wise so `/ws-evil` is not inside `/ws`), and must *also* be
//!   inside after resolving symlinks through the deepest part of the path
//!   that exists today. Any filesystem error other than "not found" fails
//!   closed.
//! - **loose** ("could this be inside?") gates *restrictive* decisions —
//!   `ask`/`ask_strong`/`deny` path rules. A relative path's location is
//!   unknown, so it counts as possibly inside; otherwise either the lexical
//!   or the symlink-resolved form being inside is enough.
//!
//! What this does not cover: a component that does not exist at check time
//! can be created (as a symlink) before the write happens — a TOCTOU window
//! inherent to checking a path the broker does not itself open. Hard links
//! are not detected. Case-insensitive filesystems are compared
//! case-sensitively, which fails safe for strict checks only.

use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

/// Resolve `.` and `..` lexically. `..` at the root stays at the root, as
/// the kernel does. Returns `None` for relative paths: without a base there
/// is nothing to normalise against.
pub fn normalize_lexical(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::Prefix(_) | Component::RootDir => out.push(c.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(s) => out.push(s),
        }
    }
    Some(out)
}

/// The path as the kernel would see it today: the deepest prefix of the
/// *original* path (so `link/..` is resolved through the link, not
/// lexically) that exists is canonicalised, and the not-yet-existing
/// remainder is appended and normalised lexically. `None` on any error other
/// than not-found, including a dangling symlink.
fn resolve_existing(path: &Path) -> Option<PathBuf> {
    for ancestor in path.ancestors() {
        if ancestor.as_os_str().is_empty() {
            break;
        }
        match std::fs::symlink_metadata(ancestor) {
            Ok(_) => {
                let base = std::fs::canonicalize(ancestor).ok()?;
                let rest = path.strip_prefix(ancestor).ok()?;
                return normalize_lexical(&base.join(rest));
            }
            Err(e) if e.kind() == ErrorKind::NotFound => continue,
            Err(_) => return None,
        }
    }
    None
}

/// Is `path` certainly inside `root`? See the module docs.
pub fn within_strict(path: &str, root: &str) -> bool {
    let (path, root) = (Path::new(path), Path::new(root));
    let (Some(lp), Some(lr)) = (normalize_lexical(path), normalize_lexical(root)) else {
        return false;
    };
    if !lp.starts_with(&lr) {
        return false;
    }
    match (resolve_existing(path), resolve_existing(root)) {
        (Some(rp), Some(rr)) => rp.starts_with(rr),
        _ => false,
    }
}

/// Could `path` be inside `root`? See the module docs.
pub fn within_loose(path: &str, root: &str) -> bool {
    let (p, r) = (Path::new(path), Path::new(root));
    let Some(lr) = normalize_lexical(r) else {
        // A relative root is a config problem (e.g. `~` with no home dir);
        // keep the old raw-prefix behaviour rather than matching everything.
        return path.starts_with(root);
    };
    let Some(lp) = normalize_lexical(p) else {
        return true;
    };
    if lp.starts_with(&lr) {
        return true;
    }
    match (resolve_existing(p), resolve_existing(r)) {
        (Some(rp), Some(rr)) => rp.starts_with(rr),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lexical_normalisation() {
        let n = |s: &str| normalize_lexical(Path::new(s)).map(|p| p.to_string_lossy().into_owned());
        assert_eq!(n("/ws/./a/../b").as_deref(), Some("/ws/b"));
        assert_eq!(n("/ws/../etc/passwd").as_deref(), Some("/etc/passwd"));
        assert_eq!(n("/../../etc").as_deref(), Some("/etc"));
        assert_eq!(n("relative/x"), None);
        assert_eq!(n(""), None);
    }

    #[test]
    fn dotdot_traversal_is_outside() {
        assert!(!within_strict("/ws/../etc/passwd", "/ws"));
        assert!(!within_strict("/ws/a/../../etc/passwd", "/ws"));
    }

    #[test]
    fn sibling_prefix_is_outside() {
        assert!(!within_strict("/ws-evil/x", "/ws"));
        assert!(!within_strict("/wsx", "/ws"));
        assert!(!within_loose("/ws-evil/x", "/ws"));
    }

    #[test]
    fn relative_paths_fail_safe() {
        assert!(!within_strict("src/main.rs", "/ws"));
        assert!(!within_strict("../ws/x", "/ws"));
        assert!(within_loose("src/main.rs", "/ws"));
    }

    #[test]
    fn nonexistent_paths_inside_are_inside() {
        let ws = tempdir("inside");
        let ws = ws.to_str().unwrap();
        assert!(within_strict(&format!("{ws}/new/dir/file.rs"), ws));
        assert!(within_strict(&format!("{ws}/./new/../file.rs"), ws));
        assert!(within_strict(ws, ws));
    }

    /// `std::env::temp_dir()` is itself behind a symlink on macOS
    /// (`/var` -> `/private/var`); both sides are resolved, so that is fine.
    #[test]
    fn root_behind_a_symlink_still_contains() {
        let ws = tempdir("root-link");
        std::fs::write(ws.join("f"), b"x").unwrap();
        assert!(within_strict(
            ws.join("f").to_str().unwrap(),
            ws.to_str().unwrap()
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escape_is_outside() {
        let ws = tempdir("ws");
        let out = tempdir("out");
        std::fs::write(out.join("secret"), b"x").unwrap();
        std::os::unix::fs::symlink(&out, ws.join("link")).unwrap();
        std::os::unix::fs::symlink(out.join("secret"), ws.join("filelink")).unwrap();
        std::os::unix::fs::symlink("/nonexistent/gatehouse", ws.join("dangling")).unwrap();
        let w = ws.to_str().unwrap();
        let p = |s: &str| format!("{w}/{s}");

        assert!(!within_strict(&p("link/secret"), w));
        assert!(!within_strict(&p("link/new-file"), w));
        assert!(!within_strict(&p("filelink"), w));
        assert!(!within_strict(&p("dangling"), w));
        // Lexically `ws/x`; the kernel resolves `link/..` to out's parent.
        assert!(!within_strict(&p("link/../x"), w));

        // Restrictive rules on the outside dir still see through the link.
        assert!(within_loose(&p("link/secret"), out.to_str().unwrap()));
    }

    fn tempdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "gh-contain-{tag}-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }
}
