use std::path::Path;

use openat::Dir;

use openat_secure::{DirSecureExt, LookupFlags};

#[test]
fn test_create_remove_dir() {
    let tmpdir = tempfile::tempdir().unwrap();
    let tmpdir = Dir::open(tmpdir.path()).unwrap();

    // Create a directory
    tmpdir
        .create_dir_secure("a", 0o777, LookupFlags::empty())
        .unwrap();

    // And a subdirectory
    tmpdir
        .create_dir_secure("a/b", 0o777, LookupFlags::empty())
        .unwrap();

    // Test for basic failure conditions of create_dir_secure()
    assert_eq!(
        tmpdir
            .create_dir_secure("", 0o777, LookupFlags::empty())
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ENOENT)
    );

    assert_eq!(
        tmpdir
            .create_dir_secure("..", 0o777, LookupFlags::empty())
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EXDEV)
    );
    assert_eq!(
        tmpdir
            .create_dir_secure("..", 0o777, LookupFlags::ALLOW_PARENT_COMPONENTS)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EXDEV)
    );
    assert_eq!(
        tmpdir
            .create_dir_secure(
                "..",
                0o777,
                LookupFlags::ALLOW_PARENT_COMPONENTS | LookupFlags::IN_ROOT
            )
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EEXIST)
    );

    assert_eq!(
        tmpdir
            .create_dir_secure("/", 0o777, LookupFlags::empty())
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EXDEV)
    );
    assert_eq!(
        tmpdir
            .create_dir_secure("/", 0o777, LookupFlags::IN_ROOT)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EEXIST)
    );

    assert_eq!(
        tmpdir
            .create_dir_secure("a/..", 0o777, LookupFlags::empty())
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EXDEV)
    );
    assert_eq!(
        tmpdir
            .create_dir_secure("a/..", 0o777, LookupFlags::ALLOW_PARENT_COMPONENTS)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EEXIST)
    );

    // Test for basic failure conditions of remove_dir_secure()
    assert_eq!(
        tmpdir
            .remove_dir_secure("", LookupFlags::empty())
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ENOENT)
    );

    assert_eq!(
        tmpdir
            .remove_dir_secure("..", LookupFlags::empty())
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EXDEV)
    );
    assert_eq!(
        tmpdir
            .remove_dir_secure("..", LookupFlags::ALLOW_PARENT_COMPONENTS)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EXDEV)
    );
    assert_eq!(
        tmpdir
            .remove_dir_secure(
                "..",
                LookupFlags::ALLOW_PARENT_COMPONENTS | LookupFlags::IN_ROOT
            )
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EBUSY)
    );

    assert_eq!(
        tmpdir
            .remove_dir_secure("/", LookupFlags::empty())
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EXDEV)
    );
    assert_eq!(
        tmpdir
            .remove_dir_secure("/", LookupFlags::IN_ROOT)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EBUSY)
    );

    assert_eq!(
        tmpdir
            .remove_dir_secure("a/..", LookupFlags::empty())
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EXDEV)
    );
    assert_eq!(
        tmpdir
            .remove_dir_secure("a/..", LookupFlags::ALLOW_PARENT_COMPONENTS)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EBUSY)
    );
    assert_eq!(
        tmpdir
            .remove_dir_secure("a/b/..", LookupFlags::ALLOW_PARENT_COMPONENTS)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ENOTEMPTY)
    );

    tmpdir
        .remove_dir_secure("a/b", LookupFlags::ALLOW_PARENT_COMPONENTS)
        .unwrap();

    tmpdir
        .remove_dir_secure("a/../a", LookupFlags::ALLOW_PARENT_COMPONENTS)
        .unwrap();
}

#[test]
fn test_symlinks() {
    let tmpdir = tempfile::tempdir().unwrap();
    let tmpdir = Dir::open(tmpdir.path()).unwrap();

    // Test for basic failure conditions of read_link_secure()
    assert_eq!(
        tmpdir
            .read_link_secure("", LookupFlags::empty())
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ENOENT)
    );
    assert_eq!(
        tmpdir
            .read_link_secure(
                "..",
                LookupFlags::IN_ROOT | LookupFlags::ALLOW_PARENT_COMPONENTS
            )
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EINVAL)
    );

    // Test for basic failure conditions of symlink_secure()
    assert_eq!(
        tmpdir
            .symlink_secure("", "b", LookupFlags::empty())
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ENOENT)
    );
    assert_eq!(
        tmpdir
            .symlink_secure(
                "..",
                "b",
                LookupFlags::IN_ROOT | LookupFlags::ALLOW_PARENT_COMPONENTS
            )
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EEXIST)
    );
    assert_eq!(
        tmpdir
            .symlink_secure(
                "/",
                "b",
                LookupFlags::IN_ROOT | LookupFlags::ALLOW_PARENT_COMPONENTS
            )
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EEXIST)
    );

    // Create a symlink
    tmpdir
        .symlink_secure(
            "../a",
            "/b",
            LookupFlags::IN_ROOT | LookupFlags::ALLOW_PARENT_COMPONENTS,
        )
        .unwrap();

    // Now read_link() it a bunch of ways
    assert_eq!(
        tmpdir.read_link_secure("a", LookupFlags::empty()).unwrap(),
        Path::new("/b")
    );
    assert_eq!(
        tmpdir.read_link_secure("/a", LookupFlags::IN_ROOT).unwrap(),
        Path::new("/b")
    );
    assert_eq!(
        tmpdir
            .read_link_secure(
                "../a",
                LookupFlags::IN_ROOT | LookupFlags::ALLOW_PARENT_COMPONENTS
            )
            .unwrap(),
        Path::new("/b")
    );
    assert_eq!(
        tmpdir
            .read_link_secure(
                "/../a",
                LookupFlags::IN_ROOT | LookupFlags::ALLOW_PARENT_COMPONENTS
            )
            .unwrap(),
        Path::new("/b")
    );
}

#[test]
fn test_remove_file() {
    let tmpdir = tempfile::tempdir().unwrap();
    let tmpdir = Dir::open(tmpdir.path()).unwrap();

    tmpdir.new_file("a", 0o666).unwrap();
    tmpdir.create_dir("b", 0o777).unwrap();

    // Escapes
    assert_eq!(
        tmpdir
            .remove_file_secure("/a", LookupFlags::empty())
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EXDEV)
    );
    assert_eq!(
        tmpdir
            .remove_file_secure("../a", LookupFlags::empty())
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EXDEV)
    );

    // EISDIR
    assert_eq!(
        tmpdir
            .remove_file_secure("/", LookupFlags::IN_ROOT)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EISDIR)
    );
    assert_eq!(
        tmpdir
            .remove_file_secure(
                "b/..",
                LookupFlags::IN_ROOT | LookupFlags::ALLOW_PARENT_COMPONENTS
            )
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EISDIR)
    );

    // ENOTDIR
    assert_eq!(
        tmpdir
            .remove_file_secure("a/", LookupFlags::IN_ROOT)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ENOTDIR)
    );

    tmpdir
        .remove_file_secure("a", LookupFlags::empty())
        .unwrap();
}
