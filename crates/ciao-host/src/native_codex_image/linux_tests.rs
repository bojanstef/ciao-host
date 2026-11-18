use super::*;

#[tokio::test]
async fn cache_hit_and_miss_stay_bound_to_the_already_held_image() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    for cached in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let paths = CiaoPaths::for_home(root.path());
        fs::create_dir_all(&paths.run_dir).unwrap();
        fs::set_permissions(&paths.run_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let a = root.path().join("A");
        let b = root.path().join("B");
        let lookup = root.path().join("mutable-backend-reference");
        fs::write(&a, b"\x7fELF-A").unwrap();
        fs::write(&b, b"\x7fELF-B").unwrap();
        symlink(&a, &lookup).unwrap();
        let (held, stamp) = crate::hook_common::native_image_identity(&lookup).unwrap();
        crate::hook_common::cached_native_version(&paths, &b, |_| async { Ok("0.170.0".into()) })
            .await
            .unwrap();
        if cached {
            cached_held_version(&paths, &held, |_| async { Ok("0.169.0".into()) })
                .await
                .unwrap();
        }
        // Model the acquisition seam of the reproduced real same-PID exec A -> B -> A.
        fs::remove_file(&lookup).unwrap();
        symlink(&b, &lookup).unwrap();
        assert_ne!(
            crate::hook_common::native_image_identity(&lookup)
                .unwrap()
                .1,
            stamp
        );
        let expected = stamp.clone();
        let (version, reused) = cached_held_version(&paths, &held, |probe| async move {
            assert!(!cached);
            assert_eq!(
                crate::hook_common::native_image_identity(&probe).unwrap().1,
                expected
            );
            Ok("0.169.0".into())
        })
        .await
        .unwrap();
        fs::remove_file(&lookup).unwrap();
        symlink(&a, &lookup).unwrap();
        assert_eq!(
            crate::hook_common::native_image_identity(&lookup)
                .unwrap()
                .1,
            stamp
        );
        assert_eq!(version, "0.169.0");
        assert_eq!(reused, cached);
    }
}

#[test]
fn private_home_is_not_under_the_temporary_directory() {
    let tx = Transaction {
        run_dir: PathBuf::from("/private/run"),
        nonce: "a".repeat(32),
        owner: Holder {
            pid: 1,
            identity: String::new(),
        },
    };
    let (home, temporary) = environment_directories(&tx);
    assert_eq!(home.parent(), temporary.parent());
    assert!(!home.starts_with(&temporary));
    assert!(!temporary.starts_with(&home));
}

#[test]
fn native_elf_architecture_is_not_just_magic_or_a_foreign_slice() {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    let mut header = [0u8; 32];
    header[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    header[16..18].copy_from_slice(&2u16.to_le_bytes());
    let native = if cfg!(target_arch = "aarch64") {
        183u16
    } else {
        62u16
    };
    header[18..20].copy_from_slice(&native.to_le_bytes());
    file.write_all(&header).unwrap();
    assert!(architecture(file.as_file()).is_some());
    for (index, value) in [(0, 0u8), (4, 1), (5, 2), (6, 0), (16, 0), (18, 0), (19, 1)] {
        let mut bytes = header;
        bytes[index] = value;
        file.as_file().write_all_at(&bytes, 0).unwrap();
        assert!(architecture(file.as_file()).is_none(), "field {index}");
    }
}

#[test]
fn linux_helper_protocol_refuses_duplicates_extra_fields_and_wrong_shapes() {
    for text in [
        r#"{"operation":"Observe","operation":"Launch"}"#,
        r#"{"operation":"Revalidate","image":{},"extra":1}"#,
        r#"{"operation":"Execute","path":"/bin/sh"}"#,
    ] {
        assert!(serde_json::from_str::<Request>(text).is_err());
    }
    for text in [
        r#"{"result":"Valid","extra":1}"#,
        r#"{"result":"Clean","result":"Valid"}"#,
        r#"{"result":"Done","image":{},"version":"0.169.0"}"#,
    ] {
        assert!(serde_json::from_str::<Frame>(text).is_err());
    }
}

#[tokio::test]
async fn first_frame_does_not_wait_for_eof_or_ignore_cancellation() {
    for cancel_now in [false, true] {
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("printf '{'; exec /bin/sleep 10")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let pid = child.id().unwrap();
        let (sender, mut receiver) = oneshot::channel();
        let sender = if cancel_now {
            drop(sender);
            None
        } else {
            Some(sender)
        };
        assert!(
            first(
                &mut child,
                Instant::now() + Duration::from_millis(100),
                &mut receiver
            )
            .await
            .is_none()
        );
        child.start_kill().unwrap();
        child.wait().await.unwrap();
        assert!(crate::process::terminal_identity(pid).await.is_none());
        drop(sender);
    }
}

#[tokio::test]
async fn malformed_or_dead_kernel_incarnation_never_becomes_image_authority() {
    assert!(
        !Holder {
            pid: 0,
            identity: String::new()
        }
        .current()
        .await
    );
    let mut own = Holder::own().await.unwrap();
    assert!(own.current().await);
    own.identity.push('x');
    assert!(!own.current().await);
    let image = ImageIdentity {
        backend: own,
        stamp: "a".repeat(32),
        architecture: NativeArchitecture::Arm64,
    };
    assert!(current_image(&image).await.is_none());
}
