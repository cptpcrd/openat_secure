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

    // And a dangerous symlink
    tmpdir.symlink("s", "..").unwrap();

    // First, a simple hardlink
    hardlink_secure(&tmpdir, "a/b", &tmpdir, "a/c", LookupFlags::empty()).unwrap();

    // Another one
    hardlink_secure(&tmpdir, "a/b", &tmpdir, "d", LookupFlags::empty()).unwrap();

    // Moving it under the symlink path fails without IN_ROOT
    assert_eq!(
        hardlink_secure(&tmpdir, "a/b", &tmpdir, "s/c", LookupFlags::empty(),)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EXDEV)
    );

    // Try again and it should succeed
    hardlink_secure(
        &tmpdir,
        "a/b",
        &tmpdir,
        "s/c",
        LookupFlags::IN_ROOT | LookupFlags::ALLOW_PARENT_COMPONENTS,
    )
    .unwrap();

    // But it didn't escape the root!
    tmpdir.metadata("c").unwrap();

    // Common failure cases
    assert_eq!(
        hardlink_secure(
            &tmpdir,
            "a/..",
            &tmpdir,
            "a/d",
            LookupFlags::ALLOW_PARENT_COMPONENTS
        )
        .unwrap_err()
        .raw_os_error(),
        Some(libc::ENOTSUP)
    );
    assert_eq!(
        hardlink_secure(
            &tmpdir,
            "/",
            &tmpdir,
            "a/d",
            LookupFlags::IN_ROOT | LookupFlags::ALLOW_PARENT_COMPONENTS,
        )
        .unwrap_err()
        .raw_os_error(),
        Some(libc::ENOTSUP)
    );
    assert_eq!(
        hardlink_secure(
            &tmpdir,
            "a/b",
            &tmpdir,
            "/",
            LookupFlags::IN_ROOT | LookupFlags::ALLOW_PARENT_COMPONENTS,
        )
        .unwrap_err()
        .raw_os_error(),
        Some(libc::EEXIST)
    );
    assert_eq!(
        hardlink_secure(
            &tmpdir,
            "a/b",
            &tmpdir,
            "a/..",
            LookupFlags::ALLOW_PARENT_COMPONENTS
        )
        .unwrap_err()
        .raw_os_error(),
        Some(libc::EEXIST)
    );
}
