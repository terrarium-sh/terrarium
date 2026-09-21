use std::fs::File;
use std::io::{self, Write};

/// Drops bytes beyond the cap; concurrent writers must use independently opened append handles.
pub fn write_capped(file: &mut File, bytes: &[u8], max_bytes: u64) -> io::Result<()> {
    file.lock()?;
    let result = (|| {
        let remaining = max_bytes.saturating_sub(file.metadata()?.len());
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

    const MAX_LOG_FILE_BYTES: u64 = 32;

    #[test]
    fn cap_drops_excess_bytes_without_truncating_existing_contents() {
        use std::io::{Read as _, Seek as _};
        let mut file = tempfile::tempfile().unwrap();
        write_capped(&mut file, b"abc", 3).unwrap();
        write_capped(&mut file, b"ignored", 3).unwrap();
        write_capped(&mut file, b"ignored", 0).unwrap();
        assert_eq!(file.metadata().unwrap().len(), 3);
        write_capped(&mut file, b"def", 5).unwrap();
        file.rewind().unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"abcde");
    }

    #[test]
    fn independent_append_handles_share_one_file_cap() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("log");
        File::create(&path)
            .unwrap()
            .set_len(MAX_LOG_FILE_BYTES - 3)
            .unwrap();
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let mut file = File::options().read(true).append(true).open(&path).unwrap();
                scope
                    .spawn(move || write_capped(&mut file, b"123456", MAX_LOG_FILE_BYTES).unwrap());
            }
        });
        assert_eq!(std::fs::metadata(path).unwrap().len(), MAX_LOG_FILE_BYTES);
    }
}
