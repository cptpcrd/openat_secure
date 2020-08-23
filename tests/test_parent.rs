use openat::Dir;

use openat_secure::DirSecureExt;

#[test]
fn test_parent() {
    // "/" has no parent
    assert!(Dir::open("/").unwrap().parent_secure().unwrap().is_none());

    // But a random temporary directory that we create does
    let tmpdir = tempfile::tempdir().unwrap();
    assert!(Dir::open(tmpdir.path())
        .unwrap()
        .parent_secure()
        .unwrap()
        .is_some());
}
