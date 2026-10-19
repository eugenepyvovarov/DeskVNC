//! Where a report of "it was bad last night" can come from.
//!
//! A session that goes wrong over a VPN is gone by the time anyone looks at
//! it: the window has been closed, and stderr was attached to a launcher
//! that threw it away. The log file is what is left afterwards.
//!
//! It is deliberately boring: one file, appended, truncated when it grows
//! past a size a person would still open. No rotation across files and no
//! timestamps in the name, because the useful question is "what happened in
//! the last hour", and that is answered by one file that keeps the tail.
//!
//! Nothing here writes secrets. The log line is produced by the same
//! `tracing` calls the rest of the app makes, and those already redact
//! credentials (`ConnectOptions` does not print them).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// How large the log may grow before it is started over.
const MAX_LOG_BYTES: u64 = 8 * 1024 * 1024;

/// The log file, and where it is.
pub struct LogFile {
    file: Mutex<std::fs::File>,
    #[cfg(test)]
    path: PathBuf,
}

impl LogFile {
    /// Open `dir/deskvnc.log`, starting over when it has grown too large.
    pub fn open(dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join("deskvnc.log");
        let too_big = std::fs::metadata(&path)
            .map(|m| m.len() > MAX_LOG_BYTES)
            .unwrap_or(false);
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        if too_big {
            // Kept, not deleted: the previous run is often the one that
            // shows what changed.
            let _ = std::fs::rename(&path, dir.join("deskvnc.previous.log"));
            return Self::open(dir);
        }
        Ok(Self {
            file: Mutex::new(file),
            #[cfg(test)]
            path,
        })
    }

    #[cfg(test)]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogFile {
    type Writer = LogWriter<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        LogWriter { file: &self.file }
    }
}

/// One log line's writer, holding the file for as long as it writes.
pub struct LogWriter<'a> {
    file: &'a Mutex<std::fs::File>,
}

impl Write for LogWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.file.lock() {
            Ok(mut file) => file.write(buf),
            // A poisoned lock means a thread died while logging. Losing the
            // line is better than taking the process down over it.
            Err(_) => Ok(buf.len()),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self.file.lock() {
            Ok(mut file) => file.flush(),
            Err(_) => Ok(()),
        }
    }
}

/// Where the log lives, next to the database and the thumbnails.
pub fn log_dir() -> Option<PathBuf> {
    directories::ProjectDirs::from("com", "deskvncviewer", "DeskVNCViewer")
        .map(|dirs| dirs.data_dir().join("logs"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use tracing_subscriber::fmt::MakeWriter as _;

    #[test]
    fn a_fresh_directory_gets_a_log_file() {
        let dir = std::env::temp_dir().join(format!("deskvnc-log-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let log = LogFile::open(&dir).expect("the log opens");
        assert!(log.path().ends_with("deskvnc.log"));
        let mut writer = log.make_writer();
        writer.write_all(b"hello\n").unwrap();
        writer.flush().unwrap();
        let text = std::fs::read_to_string(log.path()).unwrap();
        assert_eq!(text, "hello\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_oversized_log_is_kept_as_the_previous_one() {
        let dir = std::env::temp_dir().join(format!("deskvnc-log-big-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("deskvnc.log"),
            vec![b'x'; (MAX_LOG_BYTES + 1) as usize],
        )
        .unwrap();
        let log = LogFile::open(&dir).expect("the log opens");
        assert_eq!(std::fs::metadata(log.path()).unwrap().len(), 0);
        assert!(dir.join("deskvnc.previous.log").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
