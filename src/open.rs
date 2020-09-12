use std::collections::LinkedList;
use std::ffi::{CStr, CString};
use std::fs;
use std::io;
use std::os::unix::prelude::*;
use std::path::{Component, Path};

use openat::Dir;

use crate::LookupFlags;

#[cfg(target_os = "linux")]
use crate::openat2;

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

pub fn open_file_secure(
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
        let mut open_how = openat2::OpenHow::new(final_flags);
        open_how.mode = Some(mode);
        // Disable magic link resolution by default -- no good can come
        // from magic links!
        open_how.resolve_flags =
            openat2::ResolveFlags::NO_MAGICLINKS | openat2::ResolveFlags::IN_ROOT;

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
    let mut parents: Vec<Dir> = Vec::new();

    let mut n_symlinks_found = 0;
    let n_symlinks_max = if lookup_flags.contains(LookupFlags::NO_SYMLINKS) {
        // Effectively disables symlink resolution
        0
    } else {
        crate::util::get_symloop_max().unwrap_or(crate::constants::DEFAULT_SYMLOOP_MAX)
    };

    let mut components = LinkedList::new();
    for component in path.components() {
        if let Some(fname) = map_component_cstring(component)? {
            components.push_back(fname);
        }
    }

    while let Some(fname) = components.pop_front() {
        if fname.as_bytes() == b"/" {
            parents.clear();
            curdir = None;
        } else if fname.as_bytes() == b".." {
            curdir = parents.pop();
        } else {
            let cur_flags = if components.is_empty() {
                final_flags
            } else {
                crate::constants::BASE_DIR_FLAGS
            };

            let open_err = match open_file_base(
                curdir.as_ref().unwrap_or(root_dir).as_raw_fd(),
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
                        // Save the previous directory
                        if let Some(olddir) = curdir {
                            parents.push(olddir);
                        } else {
                            // If curdir is None, then parents should be empty
                            debug_assert!(parents.is_empty());
                        }

                        // Advance to the new directory
                        curdir = Some(unsafe { Dir::from_raw_fd(file.into_raw_fd()) });
                        None
                    }
                }
                Err(e) => Some(e),
            };

            if let Some(open_err) = open_err {
                // An error occurred

                let open_errno = open_err.raw_os_error().unwrap_or(0);

                #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
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

                    let target = match curdir
                        .as_ref()
                        .unwrap_or(root_dir)
                        .read_link(fname.as_c_str())
                    {
                        // Successfully read the symlink
                        Ok(t) => t,

                        // EINVAL means it's not a symlink
                        Err(e) if e.raw_os_error() == Some(libc::EINVAL) => {
                            return Err(if open_errno == libc::ENOTDIR {
                                // All we knew was that it wasn't a directory, so it's probably
                                // another file type.
                                open_err
                            } else {
                                // We got ELOOP, indicating it *was* a symlink. Then we got EINVAL,
                                // indicating that it *wasn't* a symlink.
                                // This probably means a race condition. Let's pass up EAGAIN.
                                io::Error::from_raw_os_error(libc::EAGAIN)
                            });
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
