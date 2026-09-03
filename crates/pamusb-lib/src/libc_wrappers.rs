use std::{
    ffi::{CStr, CString, c_char},
    io,
    ptr::null,
};

pub fn gethostname() -> io::Result<CString> {
    // SAFETY: libc::utsname is just a struct of byte arrays,
    // zeroing all fields is equivalent setting all fields to zero length strings,
    // this is fine
    let mut utsname: libc::utsname = unsafe { std::mem::zeroed() };

    // SAFETY: utsname is mutable and of the correct type and not borrowed
    if 0 != unsafe { libc::uname(&mut utsname as *mut libc::utsname) } {
        // According to manpage, this can only fail if the pointer is invalid,
        // which is not the case
        let error_kind = io::Error::last_os_error().kind();
        return Err(io::Error::new(
            error_kind,
            "BUG: uname syscall failed unexpectedly (this should be impossible)",
        ));
    }

    // Make sure there's a nul terminator.
    assert!(utsname.nodename.contains(&0));

    // SAFETY: We checked for the null terminator,
    // all other requirements for the pointer are already required by the slice
    let hostname = unsafe { CStr::from_ptr(&utsname.nodename[0] as *const c_char) };
    Ok(hostname.to_owned())
}

pub mod flags {
    use libc::*;
    wrapper_utils::decl_bitflags! {
        repr = c_ulong;

        Mount {
            MS_DIRSYNC,
            MS_LAZYTIME,
            MS_MANDLOCK,
            MS_NOATIME,
            MS_NODEV,
            MS_NODIRATIME,
            MS_NOEXEC,
            MS_NOSUID,
            MS_RDONLY,
            MS_REC,
            MS_RELATIME,
            MS_SILENT,
            MS_STRICTATIME,
            MS_SYNCHRONOUS,
            MS_NOSYMFOLLOW,
            MS_SHARED,
            MS_PRIVATE,
            MS_SLAVE,
            MS_UNBINDABLE,
        }
    }
    wrapper_utils::decl_bitflags! {
        repr = c_int;

        Unmount {
            MNT_FORCE,
            MNT_DETACH,
            MNT_EXPIRE,
            UMOUNT_NOFOLLOW,
        }
    }
}
pub fn mount(source: &CStr, target: &CStr, fs_type: &CStr, flags: flags::Mount) -> io::Result<()> {
    // SAFETY:
    // First 3 arguments come from &CStr, which is already guaranteed to be valid.
    // Flags might include an invalid combination, leading to EINVAL, but this is not UB.
    // data is always allowed to be null (interpreted as not setting any options)
    if 0 != unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fs_type.as_ptr(),
            flags.bits(),
            null(),
        )
    } {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn unmount(target: &CStr, flags: flags::Unmount) -> io::Result<()> {
    // SAFETY:
    // Target is guaranteed to be a valid CStr,
    // flags are allowed to be invalid, leading to EINVAL
    if 0 != unsafe { libc::umount2(target.as_ptr(), flags.bits()) } {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Retries if the syscall is interrupted
/// Returns the number of bytes written, which may be less than the length of the buffer,
/// but will never be 0
pub fn getrandom(buffer: &mut [u8], secure: bool) -> io::Result<usize> {
    let flags = if secure { libc::GRND_RANDOM } else { 0 };
    loop {
        // SAFETY: buffer pointer and length are valid because they come from a Rust slice.
        // The flags because they're just GRND_RANDOM or 0, which are both valid.
        return match unsafe { libc::getrandom(buffer.as_mut_ptr().cast(), buffer.len(), flags) } {
            -1 => {
                let err = io::Error::last_os_error();
                if matches!(err.kind(), io::ErrorKind::Interrupted) {
                    continue;
                }
                Err(err)
            }
            // (based on man 2 getrandom I think this is unreachable, but I'm not sure)
            0 => Err(io::ErrorKind::WouldBlock.into()),
            bytes_written => Ok(bytes_written as usize),
        };
    }
}
/// Higher level wrapper over [`getrandom`],
/// always tries to fill the whole buffer
pub fn getrandom_full(buffer: &mut [u8], secure: bool) -> io::Result<()> {
    let mut offset: usize = 0;
    while offset != buffer.len() {
        let subbuf = &mut buffer[offset..];
        offset += getrandom(subbuf, secure)?;
    }
    Ok(())
}

pub fn getuid() -> libc::uid_t {
    // SAFETY: getuid is always safe
    unsafe { libc::getuid() }
}
