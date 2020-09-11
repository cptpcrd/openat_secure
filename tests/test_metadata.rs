use openat::Dir;

use openat_secure::{DirSecureExt, LookupFlags};

fn same_meta(meta1: &openat::Metadata, meta2: &openat::Metadata) -> bool {
    let st1 = meta1.stat();
    let st2 = meta2.stat();

    st1.st_dev == st2.st_dev && st1.st_ino == st2.st_ino
}

fn unwrap_err<T, E>(r: Result<T, E>) -> E {
    match r {
        Ok(_) => panic!("unwrap_err() on Ok() value"),
        Err(e) => e,
    }
}

#[test]
fn test_metadata() {
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

    let meta_root = tmpdir.self_metadata().unwrap();
    let meta_a = tmpdir.metadata("a").unwrap();
    let meta_a_b = tmpdir.metadata("a/b").unwrap();

    assert!(same_meta(
        &tmpdir.metadata_secure("/", LookupFlags::empty()).unwrap(),
        &meta_root
    ));
    assert!(same_meta(
        &tmpdir.metadata_secure("..", LookupFlags::empty()).unwrap(),
        &meta_root
    ));

    assert!(same_meta(
        &tmpdir.metadata_secure("a", LookupFlags::empty()).unwrap(),
        &meta_a
    ));
    assert!(same_meta(
        &tmpdir.metadata_secure("/a", LookupFlags::empty()).unwrap(),
        &meta_a
    ));
    assert!(same_meta(
        &tmpdir
            .metadata_secure("../a", LookupFlags::empty())
            .unwrap(),
        &meta_a
    ));

    assert!(same_meta(
        &tmpdir
            .metadata_secure("../a", LookupFlags::empty())
            .unwrap(),
        &meta_a
    ));
    assert!(same_meta(
        &tmpdir
            .metadata_secure("/../a", LookupFlags::empty())
            .unwrap(),
        &meta_a
    ));

    assert!(same_meta(
        &tmpdir.metadata_secure("a/b", LookupFlags::empty()).unwrap(),
        &meta_a_b
    ));
    assert!(same_meta(
        &tmpdir
            .metadata_secure("/a/b", LookupFlags::empty())
            .unwrap(),
        &meta_a_b
    ));
    assert!(same_meta(
        &tmpdir
            .metadata_secure("../a/b", LookupFlags::empty())
            .unwrap(),
        &meta_a_b
    ));

    assert_eq!(
        unwrap_err(tmpdir.metadata_secure("a/b/", LookupFlags::empty())).raw_os_error(),
        Some(libc::ENOTDIR)
    );
}
