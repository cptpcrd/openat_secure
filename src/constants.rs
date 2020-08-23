#[cfg(target_os = "linux")]
pub const BASE_DIR_FLAGS: libc::c_int = libc::O_PATH | libc::O_DIRECTORY;
#[cfg(not(target_os = "linux"))]
pub const BASE_DIR_FLAGS: libc::c_int = libc::O_DIRECTORY;

// Linux's default (it seems util::get_symloop_max() always fails on glibc)
pub const DEFAULT_SYMLOOP_MAX: usize = 40;
