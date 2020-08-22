use std::ffi::{CStr, CString, OsStr};
use std::io;
use std::os::unix::prelude::*;
use std::path::Path;

use bitflags::bitflags;

const O_CREAT: i32 = libc::O_CREAT as i32;
const O_TMPFILE: i32 = libc::O_TMPFILE as i32;

// This is correct for every architecture except alpha, which
// Rust does not support
const SYS_OPENAT: libc::c_long = 437;

bitflags! {
    pub struct ResolveFlags: u64 {
        const NO_XDEV = 0x01;
        const NO_MAGICLINKS = 0x02;
        const NO_SYMLINKS = 0x04;
        const BENEATH = 0x08;
        const IN_ROOT = 0x10;
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct OpenHow {
    pub flags: i32,
    pub mode: Option<u32>,
    pub resolve_flags: ResolveFlags,
}

impl OpenHow {
    pub fn new(flags: i32) -> Self {
        Self {
            flags,
            mode: None,
            resolve_flags: ResolveFlags::empty(),
        }
    }

    fn raw_mode(&self) -> u64 {
        if let Some(mode) = self.mode {
            mode as u64
        } else if self.flags & O_CREAT == O_CREAT || self.flags & O_TMPFILE == O_TMPFILE {
            0o777
        } else {
            0
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
#[repr(C)]
struct RawOpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

impl From<&OpenHow> for RawOpenHow {
    fn from(other: &OpenHow) -> Self {
        Self {
            flags: (other.flags | libc::O_CLOEXEC) as u64,
            mode: other.raw_mode(),
            resolve: other.resolve_flags.bits(),
        }
    }
}

fn openat2_sys(dirfd: Option<RawFd>, path: &CStr, how: &OpenHow) -> io::Result<RawFd> {
    let dirfd = dirfd.unwrap_or(libc::AT_FDCWD);
    let mut raw_how: RawOpenHow = how.into();

    let fd = unsafe {
        libc::syscall(
            SYS_OPENAT,
            dirfd,
            path.as_ptr(),
            &mut raw_how as *mut RawOpenHow,
            std::mem::size_of::<RawOpenHow>(),
        )
    };

    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd as RawFd)
    }
}

pub fn openat2<P: AsRef<Path>>(dirfd: Option<RawFd>, path: P, how: &OpenHow) -> io::Result<RawFd> {
    let c_path = CString::new(OsStr::new(path.as_ref()).as_bytes())?;

    openat2_sys(dirfd, &c_path, how)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_how() {
        let mut how = OpenHow::new(libc::O_RDONLY);
        assert_eq!(
            how,
            OpenHow {
                flags: libc::O_RDONLY,
                mode: None,
                resolve_flags: ResolveFlags::empty(),
            }
        );

        // The main purpose here is to test the handling of the 'mode' value.

        assert_eq!(
            RawOpenHow::from(&how),
            RawOpenHow {
                flags: (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
                mode: 0,
                resolve: 0,
            }
        );

        how.mode = Some(0o700);
        assert_eq!(
            RawOpenHow::from(&how),
            RawOpenHow {
                flags: (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
                mode: 0o700,
                resolve: 0,
            }
        );

        how.mode = None;
        how.flags = libc::O_WRONLY | libc::O_CREAT;
        assert_eq!(
            RawOpenHow::from(&how),
            RawOpenHow {
                flags: (libc::O_WRONLY | libc::O_CREAT | libc::O_CLOEXEC) as u64,
                mode: 0o777,
                resolve: 0,
            }
        );

        how.mode = Some(0o700);
        assert_eq!(
            RawOpenHow::from(&how),
            RawOpenHow {
                flags: (libc::O_WRONLY | libc::O_CREAT | libc::O_CLOEXEC) as u64,
                mode: 0o700,
                resolve: 0,
            }
        );
    }

    #[test]
    fn test_openat2() {
        if openat2(None, "", &OpenHow::new(libc::O_RDONLY))
            .unwrap_err()
            .raw_os_error()
            == Some(libc::ENOENT)
        {
            test_openat2_present();
        } else {
            test_openat2_absent();
        }
    }

    fn test_openat2_present() {
        let fd = openat2(None, "/", &OpenHow::new(libc::O_RDONLY)).unwrap();
        unsafe {
            std::fs::File::from_raw_fd(fd);
        }
    }

    fn test_openat2_absent() {
        assert_eq!(
            openat2(None, "/", &OpenHow::new(libc::O_RDONLY))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENOSYS),
        );
    }
}
