use std::io;

fn same_stat(st1: &libc::stat, st2: &libc::stat) -> bool {
    st1.st_dev == st2.st_dev && st1.st_ino == st2.st_ino
}

pub fn same_dir(d1: &openat::Dir, d2: &openat::Dir) -> io::Result<bool> {
    Ok(same_stat(
        d1.self_metadata()?.stat(),
        d2.self_metadata()?.stat(),
    ))
}

pub fn get_symloop_max() -> Option<usize> {
    let res = unsafe { libc::sysconf(libc::_SC_SYMLOOP_MAX) };

    if res >= 0 {
        // A C long might be larger than a usize, but values that high (>= 2 ** 31 or 2 ** 63!)
        // should never occur in SYMLOOP_MAX.
        Some(res as usize)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_same_dir() {
        let root1 = openat::Dir::open("/").unwrap();
        let root2 = openat::Dir::open("/").unwrap();
        assert!(same_dir(&root1, &root1).unwrap());
        assert!(same_dir(&root1, &root2).unwrap());

        let tmpdir = tempfile::tempdir().unwrap();
        let dir = openat::Dir::open(tmpdir.path()).unwrap();
        assert!(!same_dir(&root1, &dir).unwrap());
    }
}
