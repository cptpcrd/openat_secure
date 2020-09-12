use std::ffi::{CStr, OsStr};
use std::fs;
use std::io;
use std::os::unix::prelude::*;
use std::path::{Path, PathBuf};

use bitflags::bitflags;
use openat::Dir;

mod constants;
mod open;
mod util;

#[cfg(target_os = "linux")]
mod openat2;

bitflags! {
    #[derive(Default)]
    pub struct LookupFlags: u64 {
        /// Don't resolve symbolic links; fail with `ELOOP` whenever one is encountered
        const NO_SYMLINKS = 1;
        /// Don't cross filesystem boundaries.
        ///
        /// On Linux, this may or may not include bind mounts by default.
        const NO_XDEV = 8;
        /// When used with `NO_XDEV` on Linux, this indicates that crossing bind mounts
        /// must be allowed (crossing other filesystem boundaries is still prohibited).
        ///
        /// WARNING: This may decrease performance.
        const XDEV_BIND_OK = 16;
    }
}

pub trait DirSecureExt {
    fn parent_secure(&self) -> io::Result<Option<Dir>>;

    fn sub_dir_secure<P: AsRef<Path>>(&self, p: P, lookup_flags: LookupFlags) -> io::Result<Dir>;

    fn new_file_secure<P: AsRef<Path>>(
        &self,
        p: P,
        mode: libc::mode_t,
        lookup_flags: LookupFlags,
    ) -> io::Result<fs::File>;
    fn update_file_secure<P: AsRef<Path>>(
        &self,
        p: P,
        mode: libc::mode_t,
        lookup_flags: LookupFlags,
    ) -> io::Result<fs::File>;
    fn open_file_secure<P: AsRef<Path>>(
        &self,
        p: P,
        lookup_flags: LookupFlags,
    ) -> io::Result<fs::File>;
    fn write_file_secure<P: AsRef<Path>>(
        &self,
        p: P,
        mode: libc::mode_t,
        lookup_flags: LookupFlags,
    ) -> io::Result<fs::File>;
    fn append_file_secure<P: AsRef<Path>>(
        &self,
        p: P,
        mode: libc::mode_t,
        lookup_flags: LookupFlags,
    ) -> io::Result<fs::File>;

    fn create_dir_secure<P: AsRef<Path>>(
        &self,
        path: P,
        mode: libc::mode_t,
        lookup_flags: LookupFlags,
    ) -> io::Result<()>;

    fn remove_dir_secure<P: AsRef<Path>>(
        &self,
        path: P,
        lookup_flags: LookupFlags,
    ) -> io::Result<()>;
    fn remove_file_secure<P: AsRef<Path>>(
        &self,
        path: P,
        lookup_flags: LookupFlags,
    ) -> io::Result<()>;

    fn list_dir_secure<P: AsRef<Path>>(
        &self,
        path: P,
        lookup_flags: LookupFlags,
    ) -> io::Result<openat::DirIter>;

    fn metadata_secure<P: AsRef<Path>>(
        &self,
        path: P,
        lookup_flags: LookupFlags,
    ) -> io::Result<openat::Metadata>;

    fn read_link_secure<P: AsRef<Path>>(
        &self,
        path: P,
        lookup_flags: LookupFlags,
    ) -> io::Result<PathBuf>;

    fn symlink_secure<P: AsRef<Path>, R: openat::AsPath>(
        &self,
        path: P,
        value: R,
        lookup_flags: LookupFlags,
    ) -> io::Result<()>;

    fn local_rename_secure<P: AsRef<Path>, R: AsRef<Path>>(
        &self,
        old: P,
        new: R,
        lookup_flags: LookupFlags,
    ) -> io::Result<()>;
}

impl DirSecureExt for Dir {
    /// Open the parent directory.
    ///
    /// This is the same as `dir.sub_dir("..")`, except that it returns `Ok(None)` if the returned
    /// directory would be the same as this directory (for example, if the directory is open to
    /// `/`).
    fn parent_secure(&self) -> io::Result<Option<Dir>> {
        let parent = self.sub_dir(unsafe { CStr::from_bytes_with_nul_unchecked(b"..\0") })?;

        Ok(if util::same_dir(self, &parent)? {
            None
        } else {
            Some(parent)
        })
    }

    /// Open a subdirectory.
    ///
    /// See the documentation of [`open_file_secure`] for security information.
    ///
    /// [`open_file_secure`]: #method.open_file_secure
    fn sub_dir_secure<P: AsRef<Path>>(&self, p: P, lookup_flags: LookupFlags) -> io::Result<Dir> {
        let fd =
            open::open_file_secure(self, p.as_ref(), lookup_flags, constants::BASE_DIR_FLAGS, 0)?;

        Ok(unsafe { Dir::from_raw_fd(fd) })
    }

    /// Atomically create a file and open it for writing. If it exists, fail with an error.
    ///
    /// See the documentation of [`open_file_secure`] for security information.
    ///
    /// [`open_file_secure`]: #method.open_file_secure
    fn new_file_secure<P: AsRef<Path>>(
        &self,
        p: P,
        mode: libc::mode_t,
        lookup_flags: LookupFlags,
    ) -> io::Result<fs::File> {
        let fd = open::open_file_secure(
            self,
            p.as_ref(),
            lookup_flags,
            libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY,
            mode,
        )?;

        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }

    /// Open a file for both reading and writing, creating it if it does not exist.
    ///
    /// See the documentation of [`open_file_secure`] for security information.
    ///
    /// [`open_file_secure`]: #method.open_file_secure
    fn update_file_secure<P: AsRef<Path>>(
        &self,
        p: P,
        mode: libc::mode_t,
        lookup_flags: LookupFlags,
    ) -> io::Result<fs::File> {
        let fd = open::open_file_secure(
            self,
            p.as_ref(),
            lookup_flags,
            libc::O_CREAT | libc::O_RDWR,
            mode,
        )?;

        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }

    /// Open a file as read-only.
    ///
    /// Unlike `open_file()`, this function ensures that the file opened is a descendant of this
    /// directory, so `/`, `..`, and symlinks cannot be used to escape it.
    ///
    /// # Lookup flags
    ///
    /// The `lookup_flags` parameter controls several aspects of how the pathname resolution is
    /// performed. See the documentation of [`LookupFlags`] for details.
    ///
    /// # Race conditions
    ///
    /// Some race conditions may cause `EAGAIN` failures. The caller may wish to retry in this
    /// case.
    ///
    /// As far as the author is aware, the only race condition that could allow escaping this
    /// directory is if files and/or directories are being concurrently moved between this
    /// directory (or a descendant directory) and other directories. For example:
    ///
    /// - `a/` (this directory)
    ///    - `b/`
    ///       - `c`
    /// - `d/`
    ///   - `e`
    ///
    /// If one process has a `Dir` pointing to `a` and is trying to open the file `b/c` using this
    /// function, and another process concurrently moves `a/b` into `d/`, then the open operation
    /// *may* succeed even though `c` is no longer in `a/`.
    ///
    /// Note, however, that this only applies to files that were descendants of this directory at
    /// some point during the concurrent modification. This function will not allow opening a file
    /// that was *never* in this directory (for example, `d/e`).
    ///
    /// [`LookupFlags`]: ./struct.LookupFlags.html
    fn open_file_secure<P: AsRef<Path>>(
        &self,
        p: P,
        lookup_flags: LookupFlags,
    ) -> io::Result<fs::File> {
        let fd = open::open_file_secure(self, p.as_ref(), lookup_flags, libc::O_RDONLY, 0)?;

        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }

    /// Open a file for writing, creating it if it does not exist and truncating it if it does.
    ///
    /// See the documentation of [`open_file_secure`] for security information.
    ///
    /// [`open_file_secure`]: #method.open_file_secure
    fn write_file_secure<P: AsRef<Path>>(
        &self,
        p: P,
        mode: libc::mode_t,
        lookup_flags: LookupFlags,
    ) -> io::Result<fs::File> {
        let fd = open::open_file_secure(
            self,
            p.as_ref(),
            lookup_flags,
            libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC,
            mode,
        )?;

        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }

    /// Open a file for appending, creating it if it does not exist.
    ///
    /// See the documentation of [`open_file_secure`] for security information.
    ///
    /// [`open_file_secure`]: #method.open_file_secure
    fn append_file_secure<P: AsRef<Path>>(
        &self,
        p: P,
        mode: libc::mode_t,
        lookup_flags: LookupFlags,
    ) -> io::Result<fs::File> {
        let fd = open::open_file_secure(
            self,
            p.as_ref(),
            lookup_flags,
            libc::O_CREAT | libc::O_WRONLY | libc::O_APPEND,
            mode,
        )?;

        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }

    fn create_dir_secure<P: AsRef<Path>>(
        &self,
        path: P,
        mode: libc::mode_t,
        lookup_flags: LookupFlags,
    ) -> io::Result<()> {
        let (subdir, fname) = prepare_inner_operation(self, path.as_ref(), lookup_flags)?;

        if let Some(fname) = fname {
            subdir.as_ref().unwrap_or(self).create_dir(fname, mode)
        } else {
            Err(std::io::Error::from_raw_os_error(libc::EEXIST))
        }
    }

    fn remove_dir_secure<P: AsRef<Path>>(
        &self,
        path: P,
        lookup_flags: LookupFlags,
    ) -> io::Result<()> {
        let (subdir, fname) = prepare_inner_operation(self, path.as_ref(), lookup_flags)?;

        if let Some(fname) = fname {
            subdir.as_ref().unwrap_or(self).remove_dir(fname)
        } else {
            let is_same = if let Some(subdir) = subdir.as_ref() {
                util::same_dir(self, subdir)?
            } else {
                true
            };

            Err(std::io::Error::from_raw_os_error(if is_same {
                libc::EBUSY
            } else {
                libc::ENOTEMPTY
            }))
        }
    }

    fn remove_file_secure<P: AsRef<Path>>(
        &self,
        path: P,
        lookup_flags: LookupFlags,
    ) -> io::Result<()> {
        let (subdir, fname) = prepare_inner_operation(self, path.as_ref(), lookup_flags)?;

        if let Some(fname) = fname {
            subdir.as_ref().unwrap_or(self).remove_file(fname)
        } else {
            Err(std::io::Error::from_raw_os_error(libc::EISDIR))
        }
    }

    #[allow(clippy::needless_return)]
    fn list_dir_secure<P: AsRef<Path>>(
        &self,
        path: P,
        lookup_flags: LookupFlags,
    ) -> io::Result<openat::DirIter> {
        let subdir = self.sub_dir_secure(path, lookup_flags)?;

        // list_self() is currently broken on Linux
        #[cfg(target_os = "linux")]
        return subdir.list_dir(".");

        #[cfg(not(target_os = "linux"))]
        return subdir.list_self();
    }

    fn metadata_secure<P: AsRef<Path>>(
        &self,
        path: P,
        lookup_flags: LookupFlags,
    ) -> io::Result<openat::Metadata> {
        let (subdir, fname) = prepare_inner_operation(self, path.as_ref(), lookup_flags)?;

        let subdir = subdir.as_ref().unwrap_or(self);

        if let Some(fname) = fname {
            subdir.metadata(fname)
        } else {
            subdir.self_metadata()
        }
    }

    fn read_link_secure<P: AsRef<Path>>(
        &self,
        path: P,
        lookup_flags: LookupFlags,
    ) -> io::Result<PathBuf> {
        let (subdir, fname) = prepare_inner_operation(self, path.as_ref(), lookup_flags)?;

        if let Some(fname) = fname {
            subdir.as_ref().unwrap_or(self).read_link(fname)
        } else {
            Err(std::io::Error::from_raw_os_error(libc::EINVAL))
        }
    }

    fn symlink_secure<P: AsRef<Path>, R: openat::AsPath>(
        &self,
        path: P,
        value: R,
        lookup_flags: LookupFlags,
    ) -> io::Result<()> {
        let (subdir, fname) = prepare_inner_operation(self, path.as_ref(), lookup_flags)?;

        if let Some(fname) = fname {
            subdir.as_ref().unwrap_or(self).symlink(fname, value)
        } else {
            Err(std::io::Error::from_raw_os_error(libc::EEXIST))
        }
    }

    fn local_rename_secure<P: AsRef<Path>, R: AsRef<Path>>(
        &self,
        old: P,
        new: R,
        lookup_flags: LookupFlags,
    ) -> io::Result<()> {
        rename_secure(self, old, self, new, lookup_flags)
    }
}

pub fn hardlink_secure<P: AsRef<Path>, R: AsRef<Path>>(
    old_dir: &Dir,
    old: P,
    new_dir: &Dir,
    new: R,
    lookup_flags: LookupFlags,
) -> io::Result<()> {
    let old = old.as_ref();

    if old.ends_with("..") {
        // As far as I can tell, there is no safe, cross-platform, race-free way to handle trailing
        // ".." components in the "old" path.
        return Err(std::io::Error::from_raw_os_error(libc::ENOTSUP));
    }

    let (old_subdir, old_fname) = prepare_inner_operation(old_dir, old, lookup_flags)?;
    let old_subdir = old_subdir.as_ref().unwrap_or(old_dir);

    let old_fname = if let Some(old_fname) = old_fname {
        old_fname
    } else {
        // Since we checked for ".." above, this means that `old` was `/`
        return Err(std::io::Error::from_raw_os_error(libc::EBUSY));
    };

    let (new_subdir, new_fname) = prepare_inner_operation(new_dir, new.as_ref(), lookup_flags)?;
    let new_subdir = new_subdir.as_ref().unwrap_or(new_dir);

    if let Some(new_fname) = new_fname {
        openat::hardlink(old_subdir, old_fname, new_subdir, new_fname)
    } else {
        Err(std::io::Error::from_raw_os_error(libc::EEXIST))
    }
}

pub fn rename_secure<P: AsRef<Path>, R: AsRef<Path>>(
    old_dir: &Dir,
    old: P,
    new_dir: &Dir,
    new: R,
    lookup_flags: LookupFlags,
) -> io::Result<()> {
    let old = old.as_ref();

    if old.ends_with("..") {
        // As far as I can tell, there is no safe, cross-platform, race-free way to handle trailing
        // ".." components in the "old" path.
        return Err(std::io::Error::from_raw_os_error(libc::ENOTSUP));
    }

    let (old_subdir, old_fname) = prepare_inner_operation(old_dir, old, lookup_flags)?;
    let old_subdir = old_subdir.as_ref().unwrap_or(old_dir);

    let old_fname = if let Some(old_fname) = old_fname {
        old_fname
    } else {
        // Since we checked for ".." above, this means that `old` was `/`
        return Err(std::io::Error::from_raw_os_error(libc::EBUSY));
    };

    let (new_subdir, new_fname) = prepare_inner_operation(new_dir, new.as_ref(), lookup_flags)?;
    let new_subdir = new_subdir.as_ref().unwrap_or(new_dir);

    if let Some(new_fname) = new_fname {
        openat::rename(old_subdir, old_fname, new_subdir, new_fname)
    } else {
        Err(std::io::Error::from_raw_os_error(libc::EEXIST))
    }
}

fn prepare_inner_operation<'a>(
    dir: &Dir,
    mut path: &'a Path,
    lookup_flags: LookupFlags,
) -> io::Result<(Option<Dir>, Option<&'a OsStr>)> {
    match path.strip_prefix("/") {
        Ok(p) => {
            // Trim the "/" prefix
            path = p;

            if path.as_os_str().is_empty() {
                // Just "/"
                return Ok((None, None));
            }
        }

        // Not an absolute path
        Err(_) => {
            if path.as_os_str().is_empty() {
                // Empty path -> ENOENT
                return Err(std::io::Error::from_raw_os_error(libc::ENOENT));
            }
        }
    }

    // We now know that `path` is not empty, and it doesn't start with a "/"

    if let Some(fname) = util::path_basename(path) {
        debug_assert!(!path.ends_with(".."));

        // Because of the conditions listed above, path.parent() should never be None
        let parent = path.parent().unwrap();

        if parent.as_os_str().is_empty() {
            // Though it might be empty, in which case we just reuse the existing directory
            Ok((None, Some(fname)))
        } else {
            Ok((Some(dir.sub_dir_secure(parent, lookup_flags)?), Some(fname)))
        }
    } else {
        debug_assert!(path.ends_with(".."));

        // So this is a path like "a/b/..". We can't really get a (containing directory, filename)
        // pair out of this.

        Ok((Some(dir.sub_dir_secure(path, lookup_flags)?), None))
    }
}
