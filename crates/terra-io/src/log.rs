use std::fs::File;
use std::io::{self, Write};

pub const MAX_LOG_FILE_BYTES: usize = 8 << 20;

/// Drops bytes beyond the cap; concurrent writers must use independently opened append handles.
pub fn write_capped(file: &mut File, bytes: &[u8]) -> io::Result<()> {
    file.lock()?;
    let result = (|| {
        let remaining = (MAX_LOG_FILE_BYTES as u64).saturating_sub(file.metadata()?.len());
        let count = bytes
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        file.write_all(&bytes[..count])
    })();
    let unlocked = file.unlock();
    result.and(unlocked)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_append_handles_share_one_file_cap() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("log");
        File::create(&path)
            .unwrap()
            .set_len(MAX_LOG_FILE_BYTES as u64 - 3)
            .unwrap();
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let mut file = File::options().read(true).append(true).open(&path).unwrap();
                scope.spawn(move || write_capped(&mut file, b"123456").unwrap());
            }
        });
        assert_eq!(
            std::fs::metadata(path).unwrap().len(),
            MAX_LOG_FILE_BYTES as u64
        );
    }
}
