use openat::Dir;

use openat_secure::{hardlink_secure, DirSecureExt, LookupFlags};

#[test]
fn test_hardlink() {
    let tmpdir = tempfile::tempdir().unwrap();
    let tmpdir = Dir::open(tmpdir.path()).unwrap();

    // Create a directory
    tmpdir
        .create_dir_secure("a", 0o777, LookupFlags::empty())
        .unwrap();
    // And a regular file inside it
    tmpdir
        .new_file_secure("a/b", 0o666, LookupFlags::empty())
        .unwrap();
    // And another directory inside it
    tmpdir
        .create_dir_secure("a/sub", 0o777, LookupFlags::empty())
        .unwrap();

    // And a dangerous symlink
    tmpdir.symlink("s", "..").unwrap();

    // First, a simple hardlink
    hardlink_secure(&tmpdir, "a/b", &tmpdir, "a/c", LookupFlags::empty()).unwrap();

    // Another one
    hardlink_secure(&tmpdir, "a/b", &tmpdir, "d", LookupFlags::empty()).unwrap();

    // Moving it under the symlink path should succeed
    hardlink_secure(&tmpdir, "a/b", &tmpdir, "s/c", LookupFlags::empty()).unwrap();

    // But it didn't escape the root!
    tmpdir.metadata("c").unwrap();

    // Common failure cases
    assert_eq!(
        hardlink_secure(&tmpdir, "a/sub/..", &tmpdir, "a/d", LookupFlags::empty())
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ENOTSUP)
    );
    assert_eq!(
        hardlink_secure(&tmpdir, "a/..", &tmpdir, "a/d", LookupFlags::empty())
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EBUSY)
    );
    assert_eq!(
        hardlink_secure(&tmpdir, "/", &tmpdir, "a/d", LookupFlags::empty())
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EBUSY)
    );
    assert_eq!(
        hardlink_secure(&tmpdir, "a/b", &tmpdir, "/", LookupFlags::empty())
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EEXIST)
    );
    assert_eq!(
        hardlink_secure(&tmpdir, "a/b", &tmpdir, "a/..", LookupFlags::empty())
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EEXIST)
    );
}
