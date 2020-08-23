use std::collections::LinkedList;
use std::ffi::{CStr, CString, OsStr};
use std::fs;
use std::io;
use std::os::unix::prelude::*;
use std::path::{Component, Path, PathBuf};

use bitflags::bitflags;
use openat::Dir;

mod util;

#[cfg(target_os = "linux")]
mod openat2;

#[cfg(target_os = "linux")]
const BASE_DIR_FLAGS: libc::c_int = libc::O_PATH | libc::O_DIRECTORY;
#[cfg(not(target_os = "linux"))]
const BASE_DIR_FLAGS: libc::c_int = libc::O_DIRECTORY;

bitflags! {
    #[derive(Default)]
    pub struct LookupFlags: u64 {
        /// Don't resolve symbolic links; fail with `ELOOP` whenever one is encountered
        const NO_SYMLINKS = 1;
        /// When resolving below a directory, act as if the process had `chroot()`ed to that
        /// directory, and treat `/`, `..`, and symlinks accordingly.
        const IN_ROOT = 2;
        /// Allow `..` components in paths and symlinks (disallowed by default).
        ///
        /// This may require large numbers of file descriptors on some systems (which is why they
        /// are not allowed by default).
        const ALLOW_PARENT_COMPONENTS = 4;
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
        let fd = open_file_secure(self, p.as_ref(), lookup_flags, BASE_DIR_FLAGS, 0)?;
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
        let fd = open_file_secure(
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
        let fd = open_file_secure(
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
        let fd = open_file_secure(self, p.as_ref(), lookup_flags, libc::O_RDONLY, 0)?;
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
        let fd = open_file_secure(
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
        let fd = open_file_secure(
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
        let path = path.as_ref();

        let (subdir, fname) = prepare_inner_operation(self, path, lookup_flags)?;

        if let Some(fname) = fname {
            subdir.as_ref().unwrap_or(self).remove_dir(fname)
        } else {
            Err(std::io::Error::from_raw_os_error(
                if path == Path::new("/") || path == Path::new("..") {
                    libc::EBUSY
                } else {
                    libc::ENOTEMPTY
                },
            ))
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

    fn list_dir_secure<P: AsRef<Path>>(
        &self,
        path: P,
        lookup_flags: LookupFlags,
    ) -> io::Result<openat::DirIter> {
        self.sub_dir_secure(path, lookup_flags)?.list_self()
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
        // Since we checked for ".." above, this probably means that `old` was `/`
        return Err(std::io::Error::from_raw_os_error(libc::ENOTSUP));
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
        // Since we checked for ".." above, this probably means that `old` was `/`
        return Err(std::io::Error::from_raw_os_error(libc::ENOTSUP));
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
            if lookup_flags.contains(LookupFlags::IN_ROOT) {
                // If we were given IN_ROOT, just trim the "/" prefix
                path = p;

                if path.as_os_str().is_empty() {
                    // Just "/"
                    return Ok((Some(dir.try_clone()?), None));
                }
            } else {
                // By default, "/" is not allowed
                return Err(std::io::Error::from_raw_os_error(libc::EXDEV));
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

    if let Some(fname) = path.file_name() {
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

        if lookup_flags.contains(LookupFlags::ALLOW_PARENT_COMPONENTS) {
            // Resolve the entire path
            Ok((Some(dir.sub_dir_secure(path, lookup_flags)?), None))
        } else {
            Err(std::io::Error::from_raw_os_error(libc::EXDEV))
        }
    }
}

fn open_file_base(
    dirfd: RawFd,
    fname: &CStr,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> io::Result<fs::File> {
    let fd = unsafe { libc::openat(dirfd, fname.as_ptr(), flags, mode as libc::c_int) };

    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }
}

fn map_component_cstring(component: Component) -> io::Result<Option<CString>> {
    Ok(match component {
        Component::CurDir => None,
        Component::RootDir => Some(CString::new(*b"/").unwrap()),
        Component::ParentDir => Some(CString::new(*b"..").unwrap()),
        Component::Normal(fname) => Some(CString::new(fname.as_bytes())?),
        // This is a Unix-only crate
        Component::Prefix(_) => unreachable!(),
    })
}

fn open_file_secure(
    root_dir: &Dir,
    path: &Path,
    lookup_flags: LookupFlags,
    mut final_flags: libc::c_int,
    mode: libc::mode_t,
) -> io::Result<RawFd> {
    #[cfg(target_os = "linux")]
    if !(lookup_flags.contains(LookupFlags::NO_XDEV)
        && lookup_flags.contains(LookupFlags::XDEV_BIND_OK))
    {
        if !lookup_flags.contains(LookupFlags::ALLOW_PARENT_COMPONENTS)
            && path.components().any(|c| c == Component::ParentDir)
        {
            return Err(io::Error::from_raw_os_error(libc::EXDEV));
        }

        let mut open_how = openat2::OpenHow::new(final_flags);
        open_how.mode = Some(mode);
        // Disable magic link resolution by default -- no good can come
        // from magic links!
        open_how.resolve_flags = openat2::ResolveFlags::NO_MAGICLINKS;

        if lookup_flags.contains(LookupFlags::NO_SYMLINKS) {
            open_how
                .resolve_flags
                .insert(openat2::ResolveFlags::NO_SYMLINKS);
        }
        if lookup_flags.contains(LookupFlags::NO_XDEV) {
            open_how
                .resolve_flags
                .insert(openat2::ResolveFlags::NO_XDEV);
        }

        if lookup_flags.contains(LookupFlags::IN_ROOT) {
            open_how
                .resolve_flags
                .insert(openat2::ResolveFlags::IN_ROOT);
        } else {
            open_how
                .resolve_flags
                .insert(openat2::ResolveFlags::BENEATH);
        }

        match openat2::openat2(Some(root_dir.as_raw_fd()), path, &open_how) {
            Ok(fd) => return Ok(fd),
            Err(e) => match e.raw_os_error().unwrap_or(0) {
                // ENOSYS means the kernel doesn't support openat2(); E2BIG means it doesn't
                // support the options that we passed
                libc::ENOSYS | libc::E2BIG => (),
                _ => return Err(e),
            },
        }
    }

    let root_dev = if lookup_flags.contains(LookupFlags::NO_XDEV) {
        root_dir.self_metadata()?.stat().st_dev as u64
    } else {
        u64::MAX
    };

    let mut curdir = None;
    let mut parents: Vec<Option<Dir>> = Vec::new();

    let mut n_symlinks_found = 0;
    let n_symlinks_max = if lookup_flags.contains(LookupFlags::NO_SYMLINKS) {
        // Effectively disables symlink resolution
        0
    } else {
        util::get_symloop_max().unwrap_or(util::DEFAULT_SYMLOOP_MAX)
    };

    let mut components = LinkedList::new();
    for component in path.components() {
        if let Some(fname) = map_component_cstring(component)? {
            components.push_back(fname);
        }
    }

    while let Some(fname) = components.pop_front() {
        if fname.as_bytes() == b"/" {
            if lookup_flags.contains(LookupFlags::IN_ROOT) {
                parents.clear();
                curdir = None;
            } else {
                return Err(io::Error::from_raw_os_error(libc::EXDEV));
            }
        } else if fname.as_bytes() == b".." {
            if !lookup_flags.contains(LookupFlags::ALLOW_PARENT_COMPONENTS) {
                return Err(io::Error::from_raw_os_error(libc::EXDEV));
            }

            if let Some(newdir) = parents.pop() {
                curdir = newdir;
            } else if !lookup_flags.contains(LookupFlags::IN_ROOT) {
                return Err(io::Error::from_raw_os_error(libc::EXDEV));
            }
        } else {
            let mut curdir_ref = if let Some(curdir_ref) = curdir.as_ref() {
                curdir_ref
            } else {
                root_dir
            };

            let cur_flags = if components.is_empty() {
                final_flags
            } else {
                BASE_DIR_FLAGS
            };

            let open_err = match open_file_base(
                curdir_ref.as_raw_fd(),
                &fname,
                cur_flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                mode,
            ) {
                Ok(file) => {
                    if lookup_flags.contains(LookupFlags::NO_XDEV)
                        && file.metadata()?.dev() != root_dev
                    {
                        return Err(io::Error::from_raw_os_error(libc::EXDEV));
                    }

                    if components.is_empty() {
                        // Final component
                        return Ok(file.into_raw_fd());
                    } else {
                        if lookup_flags.contains(LookupFlags::ALLOW_PARENT_COMPONENTS) {
                            parents.push(curdir.take());
                        }

                        curdir = Some(unsafe { Dir::from_raw_fd(file.into_raw_fd()) });
                        curdir_ref = curdir.as_ref().unwrap();
                        None
                    }
                }
                Err(e) => Some(e),
            };

            if let Some(open_err) = open_err {
                // An error occurred

                let open_errno = open_err.raw_os_error().unwrap_or(0);

                #[cfg(target_os = "freebsd")]
                let open_errno = if open_errno == libc::EMLINK {
                    libc::ELOOP
                } else {
                    open_errno
                };

                #[cfg(target_os = "netbsd")]
                let open_errno = if open_errno == libc::EFTYPE {
                    libc::ELOOP
                } else {
                    open_errno
                };

                if open_errno == libc::ELOOP || open_errno == libc::ENOTDIR {
                    // The path may be a symbolic link.
                    // If open_errno is ELOOP, it definitely is.
                    // If open_errno is ENOTDIR, then it *might* be. Or it could just be a regular
                    // file (or a block/character special, etc.).

                    // Let's try to `readlink()` it.

                    let target = match curdir_ref.read_link(fname.as_c_str()) {
                        // Successfully read the symlink
                        Ok(t) => t,

                        // EINVAL means it's not a symlink
                        Err(e) if e.raw_os_error() == Some(libc::EINVAL) => {
                            return if open_errno == libc::ENOTDIR {
                                // All we knew was that it wasn't a directory, so it's probably
                                // another file type.
                                Err(open_err)
                            } else {
                                // We got ELOOP, indicating it *was* a symlink. Then we got EINVAL,
                                // indicating that it *wasn't* a symlink.
                                // This probably means a race condition. Let's pass up EAGAIN.
                                Err(std::io::Error::from_raw_os_error(libc::EAGAIN))
                            };
                        }

                        // Pass other errors up
                        Err(e) => return Err(e),
                    };

                    // If we got here, we know it's definitely a symlink.

                    // Manually implement the maximum link count check.
                    // n_symlinks_max is 0 if we were given the NO_SYMLINKS lookup flag, so this
                    // implicitly handles that case too.
                    if n_symlinks_found >= n_symlinks_max {
                        return Err(io::Error::from_raw_os_error(libc::ELOOP));
                    }
                    n_symlinks_found += 1;

                    // If we were doing the final lookup and the symbolic link target ends with a
                    // '/', that means the final file has to be a directory.
                    // So add O_DIRECTORY to the flags.
                    if components.is_empty() && target.as_os_str().as_bytes().ends_with(b"/") {
                        final_flags |= libc::O_DIRECTORY;
                    }

                    // Add the other elements to the queue
                    // The ordering is weird, but basically we add them in order at the front
                    for target_component in target.components().rev() {
                        if let Some(fname) = map_component_cstring(target_component)? {
                            components.push_front(fname);
                        }
                    }
                } else {
                    return Err(open_err);
                }
            }
        }
    }

    if let Some(d) = curdir {
        Ok(d.into_raw_fd())
    } else {
        Ok(root_dir.try_clone()?.into_raw_fd())
    }
}
