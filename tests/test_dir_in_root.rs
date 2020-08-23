use openat::Dir;

use openat_secure::{DirSecureExt, LookupFlags};

fn same_stat(st1: &libc::stat, st2: &libc::stat) -> bool {
    st1.st_dev == st2.st_dev && st1.st_ino == st2.st_ino
}

fn same_dir(d1: &openat::Dir, d2: &openat::Dir) -> std::io::Result<bool> {
    Ok(same_stat(
        d1.self_metadata()?.stat(),
        d2.self_metadata()?.stat(),
    ))
}

#[test]
fn test_basic_in_root() {
    test_basic_in_root_generic(LookupFlags::IN_ROOT);

    // On Linux, this specific flag combination prevents optimization using openat2()
    #[cfg(target_os = "linux")]
    test_basic_in_root_generic(
        LookupFlags::IN_ROOT | LookupFlags::NO_XDEV | LookupFlags::XDEV_BIND_OK,
    );
}

fn test_basic_in_root_generic(base_flags: LookupFlags) {
    let tmpdir = tempfile::tempdir().unwrap();
    let tmpdir = Dir::open(tmpdir.path()).unwrap();

    tmpdir.create_dir("a", 0o777).unwrap();
    tmpdir.create_dir("a/b", 0o777).unwrap();
    tmpdir.new_file("c", 0o666).unwrap();
    tmpdir.symlink("d", "c").unwrap();
    tmpdir.symlink("e", "/c").unwrap();
    tmpdir.symlink("f", "a/b").unwrap();
    tmpdir.symlink("a/b/g", "../..").unwrap();
    tmpdir.symlink("h", "c/").unwrap();

    // We can open "a", and it's not the same as the main directory
    assert!(!same_dir(&tmpdir, &tmpdir.sub_dir_secure("a", base_flags).unwrap(),).unwrap());
    // Same with "a/."
    assert!(!same_dir(&tmpdir, &tmpdir.sub_dir_secure("a/.", base_flags).unwrap(),).unwrap());

    // And "a/b"
    assert!(!same_dir(&tmpdir, &tmpdir.sub_dir_secure("a/b", base_flags).unwrap(),).unwrap());
    // And "a/b/."
    assert!(!same_dir(
        &tmpdir,
        &tmpdir.sub_dir_secure("a/b/.", base_flags).unwrap(),
    )
    .unwrap());

    // But not "a/.." or "a/../.."
    assert_eq!(
        tmpdir
            .sub_dir_secure("a/..", base_flags)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EXDEV)
    );
    assert_eq!(
        tmpdir
            .sub_dir_secure("a/../..", base_flags)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EXDEV)
    );

    // Unless we specify ALLOW_PARENT_COMPONENTS (and then it's the same as the main directory
    assert!(same_dir(
        &tmpdir,
        &tmpdir
            .sub_dir_secure("a/..", base_flags | LookupFlags::ALLOW_PARENT_COMPONENTS)
            .unwrap()
    )
    .unwrap());

    assert!(same_dir(
        &tmpdir,
        &tmpdir
            .sub_dir_secure("a/../..", base_flags | LookupFlags::ALLOW_PARENT_COMPONENTS)
            .unwrap()
    )
    .unwrap());

    // Same with ".." and "/"
    assert_eq!(
        tmpdir
            .sub_dir_secure("..", base_flags)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EXDEV)
    );
    assert!(same_dir(&tmpdir, &tmpdir.sub_dir_secure("/", base_flags).unwrap()).unwrap());
    assert!(same_dir(
        &tmpdir,
        &tmpdir
            .sub_dir_secure("..", base_flags | LookupFlags::ALLOW_PARENT_COMPONENTS)
            .unwrap()
    )
    .unwrap());
    assert!(same_dir(
        &tmpdir,
        &tmpdir
            .sub_dir_secure("/", base_flags | LookupFlags::ALLOW_PARENT_COMPONENTS)
            .unwrap()
    )
    .unwrap());

    // We can open "c" (a regular file)
    tmpdir.open_file_secure("c", base_flags).unwrap();
    // And "d" (a relative symlink to "c")
    tmpdir.open_file_secure("d", base_flags).unwrap();
    // Unless we specify NO_SYMLINKS
    assert_eq!(
        tmpdir
            .sub_dir_secure("d", base_flags | LookupFlags::NO_SYMLINKS)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ELOOP)
    );
    // And "e" (an absolute symlink to "/c")
    tmpdir.open_file_secure("e", base_flags).unwrap();
    // Unless we specify NO_SYMLINKS
    assert_eq!(
        tmpdir
            .sub_dir_secure("e", base_flags | LookupFlags::NO_SYMLINKS)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ELOOP)
    );

    // We can't open "c" as a subdirectory
    assert_eq!(
        tmpdir
            .sub_dir_secure("c", base_flags)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ENOTDIR)
    );

    // We can open "f" (a relative symlink to a/b)
    tmpdir.sub_dir_secure("f", base_flags).unwrap();
    // Unless we specify NO_SYMLINKS
    assert_eq!(
        tmpdir
            .sub_dir_secure("f", base_flags | LookupFlags::NO_SYMLINKS)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ELOOP)
    );
    // But we can't use "../../.." from there to escape
    assert!(same_dir(
        &tmpdir,
        &tmpdir
            .sub_dir_secure(
                "f/../../..",
                base_flags | LookupFlags::ALLOW_PARENT_COMPONENTS
            )
            .unwrap()
    )
    .unwrap());

    // We can also open "a/b/g" (a relative symlink to "../..")
    // And it's the same as the main directory
    assert!(same_dir(
        &tmpdir,
        &tmpdir
            .sub_dir_secure("a/b/g", base_flags | LookupFlags::ALLOW_PARENT_COMPONENTS)
            .unwrap()
    )
    .unwrap());
    // But we can't use ".." from there to escape
    assert!(same_dir(
        &tmpdir,
        &tmpdir
            .sub_dir_secure(
                "a/b/g/..",
                base_flags | LookupFlags::ALLOW_PARENT_COMPONENTS
            )
            .unwrap()
    )
    .unwrap());

    // "h" is a symlink to "c/". "c" is a regular file, so this should fail with ENOTDIR.
    assert_eq!(
        tmpdir
            .sub_dir_secure("h", base_flags)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ENOTDIR)
    );
    // But if we specify NO_SYMLINKS it fails with ELOOP
    assert_eq!(
        tmpdir
            .sub_dir_secure("h", base_flags | LookupFlags::NO_SYMLINKS)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ELOOP)
    );
}
