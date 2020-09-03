use std::collections::HashSet;
use std::ffi::OsString;
use std::io;

use openat::Dir;

use openat_secure::{DirSecureExt, LookupFlags};

fn collect_entries(it: openat::DirIter) -> io::Result<HashSet<OsString>> {
    let mut res = HashSet::new();

    for entry in it {
        res.insert(entry?.file_name().into());
    }

    Ok(res)
}

#[test]
fn test_list_dir() {
    let tmpdir = tempfile::tempdir().unwrap();
    let tmpdir = Dir::open(tmpdir.path()).unwrap();

    // Create a dangerous symlink
    tmpdir.symlink("s", "..").unwrap();

    let root_entries = collect_entries(tmpdir.list_dir(".").unwrap()).unwrap();

    // Fails without IN_ROOT
    assert_eq!(
        tmpdir
            .list_dir_secure("s", LookupFlags::empty())
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EXDEV)
    );

    assert_eq!(
        collect_entries(tmpdir.list_dir_secure("s", LookupFlags::IN_ROOT).unwrap()).unwrap(),
        root_entries
    );
}
