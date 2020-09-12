use openat::Dir;

use openat_secure::{DirSecureExt, LookupFlags};

#[test]
fn test_local_rename() {
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

    // First, a simple rename
    tmpdir
        .local_rename_secure("a/b", "a/c", LookupFlags::empty())
        .unwrap();

    // Renaming it under the symlink should succeed
    tmpdir
        .local_rename_secure("a/c", "s/c", LookupFlags::empty())
        .unwrap();

    // But it won't escape the root!
    tmpdir.metadata("c").unwrap();

    // Common failure cases
    assert_eq!(
        tmpdir
            .local_rename_secure("a/sub/..", "d", LookupFlags::empty())
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ENOTSUP)
    );
    assert_eq!(
        tmpdir
            .local_rename_secure("a/..", "d", LookupFlags::empty())
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EBUSY)
    );
    assert_eq!(
        tmpdir
            .local_rename_secure("/", "d", LookupFlags::empty())
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EBUSY)
    );
    assert_eq!(
        tmpdir
            .local_rename_secure("c", "a/sub/..", LookupFlags::empty())
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ENOTEMPTY)
    );
    assert_eq!(
        tmpdir
            .local_rename_secure("c", "a/..", LookupFlags::empty())
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EBUSY)
    );
    assert_eq!(
        tmpdir
            .local_rename_secure("c", "/", LookupFlags::empty())
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EBUSY)
    );
}
