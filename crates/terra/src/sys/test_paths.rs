//! Everything a test thread resolves paths against: its own home. Thread-local
//! so parallel tests never fake each other's environment.

use std::path::{Path, PathBuf};

thread_local! {
    static TEST: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

/// A home of this test's own, as the paths built on it.
pub(crate) struct TestHome(tempfile::TempDir);

impl TestHome {
    pub(crate) fn new() -> Self {
        // macOS's `$TMPDIR` is long enough to push box sockets past `MAX_SOCK_PATH`.
        #[cfg(unix)]
        let dir = tempfile::tempdir_in("/tmp");
        #[cfg(not(unix))]
        let dir = tempfile::tempdir();
        let dir = dir.expect("a temporary home for this test");
        TEST.with_borrow_mut(|t| {
            *t = Some(dir.path().to_path_buf());
        });
        Self(dir)
    }

    pub(crate) fn get_path(&self) -> &Path {
        self.0.path()
    }
}

impl Drop for TestHome {
    fn drop(&mut self) {
        TEST.with_borrow_mut(|t| *t = None);
    }
}

/// This thread's home, for [`super::resolve_home_dir`].
pub(crate) fn get_test_home() -> Option<PathBuf> {
    TEST.with_borrow(Clone::clone)
}
