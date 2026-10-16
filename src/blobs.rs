//! Blob files: where they live, putting new ones in place, and the cache of
//! open mappings that serving reads from.
//!
//! Files are content-addressed under `blobs/ab/cd/<sha256>`, a brotli copy
//! beside each as `<sha256>.br`. New files are written under `tmp/`, flushed,
//! and renamed into place, so a half-written blob is never visible. Only
//! blobs over [`INLINE_MAX`](crate::store::INLINE_MAX) are files.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use bytes::Bytes;
use lru::LruCache;
use parking_lot::Mutex;

use crate::hash::Hash;

pub struct Files {
    root: PathBuf,
    tmp: PathBuf,
    /// Mappings by (seq, brotli copy), each holding its file open.
    mapped: Mutex<LruCache<(u64, bool), Bytes>>,
}

impl Files {
    /// Open the store under `data`, clearing what an earlier run left in
    /// `tmp/`.
    pub fn open(data: &Path, open_files: usize) -> io::Result<Files> {
        let root = data.join("blobs");
        let tmp = data.join("tmp");
        std::fs::create_dir_all(&root)?;
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp)?;
        let capacity = std::num::NonZeroUsize::new(open_files.max(1)).expect("non-zero");
        Ok(Files {
            root,
            tmp,
            mapped: Mutex::new(LruCache::new(capacity)),
        })
    }

    pub fn path(&self, hash: &Hash, brotli: bool) -> PathBuf {
        let hex = hash.hex();
        let name = if brotli {
            format!("{hex}.br")
        } else {
            hex.clone()
        };
        self.root.join(&hex[..2]).join(&hex[2..4]).join(name)
    }

    /// A new file in `tmp/`, removed when dropped unless it's been
    /// [placed](Self::place).
    pub fn temp(&self) -> io::Result<TempFile> {
        let mut name = [0u8; 12];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut name)
            .map_err(|_| io::Error::other("no randomness"))?;
        let path = self.tmp.join(hex::encode(name));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        Ok(TempFile {
            path,
            file: Some(file),
        })
    }

    /// Move a finished temp file into place. Neither its bytes nor its name
    /// are on disk for sure until [`sync`](Self::sync).
    pub fn place(&self, mut tmp: TempFile, hash: &Hash, brotli: bool) -> io::Result<()> {
        let target = self.path(hash, brotli);
        std::fs::create_dir_all(target.parent().expect("a fanout directory"))?;
        drop(tmp.file.take());
        std::fs::rename(&tmp.path, &target)?;
        tmp.path = PathBuf::new();
        Ok(())
    }

    /// Flush everything written to the blobs' filesystem: every placed
    /// file's bytes and name, at once. One `syncfs` a batch costs a journal
    /// commit or two; an fsync per file and per directory cost that each.
    pub fn sync(&self) -> io::Result<()> {
        let dir = File::open(&self.root)?;
        // SAFETY: syncfs on an open descriptor.
        if unsafe { libc::syncfs(std::os::fd::AsRawFd::as_raw_fd(&dir)) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// A blob's file, mapped, if the cache has it.
    pub fn cached(&self, seq: u64, brotli: bool) -> Option<Bytes> {
        self.mapped.lock().get(&(seq, brotli)).cloned()
    }

    /// Map a blob's file and keep the mapping. Blocks on the disk: call it
    /// off the async threads.
    pub fn map(&self, seq: u64, hash: &Hash, brotli: bool) -> io::Result<Bytes> {
        if let Some(b) = self.cached(seq, brotli) {
            return Ok(b);
        }
        let file = open_noatime(&self.path(hash, brotli))?;
        let len = file.metadata()?.len();
        let bytes = if len == 0 {
            Bytes::new()
        } else {
            // SAFETY: blob files are written once, under tmp/, and never
            // changed after they're renamed into place.
            let map = unsafe { memmap2::Mmap::map(&file)? };
            // Start reading it in now, so the sendfile that follows waits on
            // the disk less, on the async thread that makes it.
            // SAFETY: advice on an open file; nothing is read or written.
            unsafe {
                libc::posix_fadvise(
                    std::os::fd::AsRawFd::as_raw_fd(&file),
                    0,
                    0,
                    libc::POSIX_FADV_WILLNEED,
                )
            };
            crate::send_file::bytes(map, file)
        };
        self.mapped.lock().put((seq, brotli), bytes.clone());
        Ok(bytes)
    }

    /// Drop a blob's mappings and remove its files.
    pub fn remove(&self, seq: u64, hash: &Hash) -> io::Result<()> {
        {
            let mut m = self.mapped.lock();
            m.pop(&(seq, false));
            m.pop(&(seq, true));
        }
        for brotli in [false, true] {
            match std::fs::remove_file(self.path(hash, brotli)) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
                _ => {}
            }
        }
        Ok(())
    }

    /// Link (or with `copy`, copy) an existing file in as a blob, for import.
    pub fn adopt(&self, from: &Path, hash: &Hash, copy: bool) -> io::Result<()> {
        let target = self.path(hash, false);
        std::fs::create_dir_all(target.parent().expect("a fanout directory"))?;
        let r = if copy {
            std::fs::copy(from, &target).map(|_| ())
        } else {
            std::fs::hard_link(from, &target)
        };
        match r {
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            r => r,
        }
    }
}

/// Open to read without updating the access time, which costs a metadata
/// write per read where the filesystem keeps it. Only a file's owner may
/// ask for that, so anyone else's opens it plainly.
pub fn open_noatime(path: &Path) -> io::Result<File> {
    match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOATIME)
        .open(path)
    {
        Err(e) if e.raw_os_error() == Some(libc::EPERM) => File::open(path),
        r => r,
    }
}

/// A file being written under `tmp/`.
pub struct TempFile {
    path: PathBuf,
    file: Option<File>,
}

impl TempFile {
    pub fn file(&mut self) -> &mut File {
        self.file.as_mut().expect("open until placed")
    }

    #[cfg(test)]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn places_temp_files_and_maps_them() {
        let dir = tempfile::tempdir().unwrap();
        let files = Files::open(dir.path(), 4).unwrap();
        let data = vec![5u8; 100_000];
        let hash = Hash::of(&data);
        let mut tmp = files.temp().unwrap();
        tmp.file().write_all(&data).unwrap();
        let tmp_path = tmp.path().to_path_buf();
        files.place(tmp, &hash, false).unwrap();
        files.sync().unwrap();
        assert!(!tmp_path.exists());
        let mapped = files.map(1, &hash, false).unwrap();
        assert_eq!(&mapped[..], &data[..]);
        assert!(crate::send_file::find(&mapped).is_some());
        assert!(files.cached(1, false).is_some());
        files.remove(1, &hash).unwrap();
        assert!(files.cached(1, false).is_none());
        assert!(!files.path(&hash, false).exists());
    }

    #[test]
    fn abandoned_temp_files_vanish() {
        let dir = tempfile::tempdir().unwrap();
        let files = Files::open(dir.path(), 4).unwrap();
        let tmp = files.temp().unwrap();
        let path = tmp.path().to_path_buf();
        assert!(path.exists());
        drop(tmp);
        assert!(!path.exists());
    }
}
