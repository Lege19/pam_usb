//! Minimal abstract IO interface
//!
//! This will make fuzzing/failpoint testing later much easier
//!
//! This is designed to be close to what pamusb needs,
//! not close to what the underlying APIs (`std::fs`, `libc::getrandom`, `libc::mount`, etc) provide
//! This makes more sense because e.g. testing code shouldn't have to provide a whole `Read` implementation
//! for the sake of being more compatiable with `std::fs`.
//!
//! This is not abstract over `std::io::Error` though,
//! since values of this type are easy to construct and must be handled correctly.

use std::{
    ffi::{CStr, CString, NulError, OsStr},
    io::{self, Read, Write},
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::Path,
};

use crate::libc_wrappers;

pub trait Rng {
    /// Fill `buf` with Cryptographically Secure RNG of some kind, blocking if neccessary
    fn getrandom(&mut self, buf: &mut [u8]) -> io::Result<()>;
}

pub trait Fs {
    /// Reads an entire file into a newly allocated buffer.
    /// This is expected to be used for configuration files.
    ///
    /// This probably shouldn't be used for secrets (it can't easily be zeroed).
    fn read(&mut self, path: impl AsRef<Path>) -> io::Result<Vec<u8>>;
    /// Reads exactly enough bytes to fill buf.
    /// Should return InvalidData is the length of the file does not exactly match the length of the buffer.
    /// Note: do not return UnexpectedEof if the file is too short. It should still be InvalidData.
    ///
    /// This is expected to be used for keys and other fixed-length secrets.
    fn read_exact(&mut self, path: impl AsRef<Path>, buf: &mut [u8]) -> io::Result<()>;
    /// Creates or opens that file and writes/overwrites its contents with the entire buffer.
    fn write(&mut self, path: impl AsRef<Path>, buf: &[u8]) -> io::Result<()>;

    type Mount: Mount;
    fn mount(&mut self, source: impl AsRef<Path>, fs_type: &OsStr) -> io::Result<Self::Mount>;
}
/// Implementors are expected to unmount on drop
pub trait Mount: AsRef<Path> {}

#[derive(Clone, Copy)]
pub struct StdFs;

fn nul_err_to_io_err(nul_err: NulError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, nul_err)
}

impl Fs for StdFs {
    fn read(&mut self, path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        std::fs::OpenOptions::new()
            .read(true)
            .open(path)?
            .read_exact(&mut out)?;
        Ok(out)
    }
    fn read_exact(&mut self, path: impl AsRef<Path>, buf: &mut [u8]) -> io::Result<()> {
        let mut f = std::fs::OpenOptions::new().read(true).open(path.as_ref())?;

        let expected_length = buf.len();
        let actual_length = f.metadata()?.len() as usize;
        if actual_length != expected_length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "File {:?} had wrong length. Expected length: {}. Actual length: {}",
                    path.as_ref(),
                    expected_length,
                    actual_length
                ),
            ));
        }

        f.read_exact(buf)?;

        Ok(())
    }
    fn write(&mut self, path: impl AsRef<Path>, buf: &[u8]) -> io::Result<()> {
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)?
            .write_all(buf)
    }

    type Mount = LibcMount;
    fn mount(&mut self, source: impl AsRef<Path>, fs_type: &OsStr) -> io::Result<Self::Mount> {
        let source =
            CString::new(source.as_ref().as_os_str().as_bytes()).map_err(nul_err_to_io_err)?;
        let fs_type = CString::new(fs_type.as_bytes()).map_err(nul_err_to_io_err)?;

        LibcMount::new(source.as_c_str(), fs_type.as_c_str())
    }
}

pub struct LibcMount(CString);
impl LibcMount {
    fn new(source: &CStr, fs_type: &CStr) -> io::Result<Self> {
        const RANDOM_NAME_LENGTH: usize = 16;
        // generate a random name for the mount point in /tmp/
        let mut random_name = String::with_capacity(RANDOM_NAME_LENGTH);
        for _ in 0..RANDOM_NAME_LENGTH {
            random_name.push(fastrand::alphanumeric());
        }
        let target = Path::new("/tmp").join(random_name);
        std::fs::create_dir_all(target.as_path())?;
        let target = CString::new(target.into_os_string().into_vec()).map_err(nul_err_to_io_err)?;

        libc_wrappers::mount(
            source,
            target.as_c_str(),
            fs_type,
            libc::MS_DIRSYNC
                | libc::MS_SYNCHRONOUS
                | libc::MS_NODEV
                | libc::MS_NOEXEC
                | libc::MS_NOSUID
                | libc::MS_NOSYMFOLLOW,
        )?;

        Ok(Self(target))
    }
}
impl Drop for LibcMount {
    fn drop(&mut self) {
        if let Err(e) =
            libc_wrappers::unmount(self.0.as_c_str(), libc::MNT_DETACH | libc::UMOUNT_NOFOLLOW)
        {
            log::error!("Failed to unmount device: {}", e);
        }
        if let Err(e) = std::fs::remove_dir(self.0.as_c_str().to_str().expect(
            "This path is always /tmp/<ascii>, so we don't need to worry about it not being UTF-8",
        )) {
            log::error!("Failed to remove temoprary directory: {}", e);
        }
    }
}
impl AsRef<Path> for LibcMount {
    fn as_ref(&self) -> &Path {
        Path::new(OsStr::from_bytes(self.0.to_bytes()))
    }
}
impl Mount for LibcMount {}

#[derive(Clone, Copy)]
pub struct Getrandom;
impl Rng for Getrandom {
    fn getrandom(&mut self, buf: &mut [u8]) -> io::Result<()> {
        libc_wrappers::getrandom_full(buf, true)
    }
}
