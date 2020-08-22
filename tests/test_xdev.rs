use openat::Dir;

use openat_secure::{DirSecureExt, LookupFlags};

#[test]
fn test_xdev() {
    let root = Dir::open("/").unwrap();

    // "/" and "/dev" should be on different filesystems

    root.sub_dir_secure("dev", LookupFlags::empty()).unwrap();

    assert_eq!(
        root.sub_dir_secure("dev", LookupFlags::NO_XDEV)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EXDEV)
    );

    assert_eq!(
        root.sub_dir_secure("dev", LookupFlags::NO_XDEV | LookupFlags::XDEV_BIND_OK)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EXDEV)
    );
}
