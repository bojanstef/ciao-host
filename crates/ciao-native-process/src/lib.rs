//! A safe, narrow boundary around macOS kernel process incarnation queries.
//!
//! Kernel process identities and original argv boundaries are not exposed by `ps`. These FFI calls avoid
//! depending on an installed Python runtime while keeping ciao-host's unsafe-code prohibition.

#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(any(target_os = "macos", test))]
const MAX_KERNEL_ARGUMENT_BYTES: usize = 256 * 1024;
#[cfg(any(target_os = "macos", test))]
const MAX_ARGUMENT_BYTES: usize = 64 * 1024;
#[cfg(any(target_os = "macos", test))]
const MAX_ARGUMENTS: usize = 256;

/// Returns original argv only. The bounded kernel buffer also contains environment data; parsing
/// stops at argc and never returns, logs, or includes that remainder in an error.
#[cfg(target_os = "macos")]
pub fn native_arguments(pid: u32) -> Option<Vec<String>> {
    use nix::libc;

    if pid == 0 {
        return None;
    }
    let pid = libc::pid_t::try_from(pid).ok()?;
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut buffer = vec![0u8; MAX_KERNEL_ARGUMENT_BYTES];
    let mut size = buffer.len();
    // SAFETY: mib has the three integers required by KERN_PROCARGS2. buffer is writable for
    // size bytes, size points to its initialized length, and no new kernel value is supplied.
    let read = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buffer.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    // XNU can return a full-size suffix when its argument area exceeds the supplied buffer.
    // Reject saturation, even on syscall success, rather than parse environment as argv.
    if read != 0 || size >= buffer.len() {
        return None;
    }
    parse_arguments(&buffer[..size])
}

#[cfg(any(target_os = "macos", test))]
fn parse_arguments(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() >= MAX_KERNEL_ARGUMENT_BYTES {
        return None;
    }
    let argc = i32::from_ne_bytes(bytes.get(..4)?.try_into().ok()?);
    let argc = usize::try_from(argc).ok()?;
    if argc == 0 || argc > MAX_ARGUMENTS {
        return None;
    }
    let executable_end = bytes.get(4..)?.iter().position(|&byte| byte == 0)? + 4;
    let executable_bytes = executable_end - 4 + 1;
    if executable_bytes <= 1 || executable_bytes > 4096 {
        return None;
    }
    std::str::from_utf8(&bytes[4..executable_end]).ok()?;
    // XNU aligns the executable_path= string region to an 8-byte pointer before argv.
    // Its hidden prefix is 16 bytes, so the exposed path has the same alignment. Skipping
    // every NUL instead would lose an empty argv[0] and spill one environment entry into argv.
    let start = 4 + executable_bytes.next_multiple_of(8);
    if bytes
        .get(executable_end + 1..start)?
        .iter()
        .any(|&byte| byte != 0)
    {
        return None;
    }
    let mut cursor = start;
    let mut arguments = Vec::with_capacity(argc);
    for _ in 0..argc {
        let end = bytes.get(cursor..)?.iter().position(|&byte| byte == 0)? + cursor;
        if end + 1 - start > MAX_ARGUMENT_BYTES {
            return None;
        }
        arguments.push(std::str::from_utf8(&bytes[cursor..end]).ok()?.to_owned());
        cursor = end + 1;
    }
    Some(arguments)
}

/// Returns a canonical boot UUID and kernel process-unique ID, or no identity when inspection
/// is incomplete or the PID changed incarnation between reads. The caller separately binds PID.
#[cfg(target_os = "macos")]
pub fn native_identity(pid: u32) -> Option<String> {
    use nix::libc;

    if pid == 0 {
        return None;
    }
    let pid = libc::pid_t::try_from(pid).ok()?;
    let mut boot = [0u8; 37];
    let mut size = boot.len();
    // SAFETY: boot is a writable buffer of size bytes; no new sysctl value is supplied.
    let read = unsafe {
        libc::sysctlbyname(
            c"kern.bootsessionuuid".as_ptr(),
            boot.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if read != 0 || size != boot.len() {
        return None;
    }
    identity_from_records(&boot, unique_id(pid)?, unique_id(pid)?)
}

#[cfg(target_os = "macos")]
fn unique_id(pid: nix::libc::pid_t) -> Option<u64> {
    // XNU proc_uniqidentifierinfo (PROC_PIDUNIQIDENTIFIERINFO, flavor 17).
    #[repr(C)]
    #[derive(Default)]
    struct UniqueInfo {
        executable_uuid: [u8; 16],
        unique_id: u64,
        parent_unique_id: u64,
        reserved: [u64; 3],
    }
    const _: () = assert!(
        std::mem::size_of::<UniqueInfo>() == 56
            && std::mem::align_of::<UniqueInfo>() == 8
            && std::mem::offset_of!(UniqueInfo, unique_id) == 16
            && std::mem::offset_of!(UniqueInfo, parent_unique_id) == 24
            && std::mem::offset_of!(UniqueInfo, reserved) == 32
    );
    let mut info = UniqueInfo::default();
    let size = 56;
    // SAFETY: info has the checked size and alignment of the flavor-17 kernel structure;
    // proc_pidinfo writes at most size bytes and retains no pointer to the stack buffer.
    let read =
        unsafe { nix::libc::proc_pidinfo(pid, 17, 1, std::ptr::from_mut(&mut info).cast(), size) };
    (read == size).then_some(info.unique_id)
}

#[cfg(any(target_os = "macos", test))]
fn identity_from_records(boot: &[u8], first: u64, second: u64) -> Option<String> {
    if boot.len() != 37 || boot[36] != 0 || first == 0 || first != second {
        return None;
    }
    let boot = std::str::from_utf8(&boot[..36]).ok()?;
    if !boot.bytes().enumerate().all(|(index, byte)| {
        if [8, 13, 18, 23].contains(&index) {
            byte == b'-'
        } else {
            byte.is_ascii_hexdigit()
        }
    }) {
        return None;
    }
    Some(format!("macos:{}:{first}", boot.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argument_record(executable: &[u8], arguments: &[&[u8]], environment: &[u8]) -> Vec<u8> {
        let mut bytes = i32::try_from(arguments.len())
            .unwrap()
            .to_ne_bytes()
            .to_vec();
        bytes.extend_from_slice(executable);
        bytes.push(0);
        while (bytes.len() - 4) % 8 != 0 {
            bytes.push(0);
        }
        for argument in arguments {
            bytes.extend_from_slice(argument);
            bytes.push(0);
        }
        bytes.extend_from_slice(environment);
        bytes
    }

    #[test]
    fn arguments_keep_boundaries_empty_values_and_never_include_environment() {
        for length in 1..=8 {
            let executable = vec![b'x'; length];
            for expected in [
                vec![
                    b"codex".as_slice(),
                    b"-c",
                    b"notify=[\"a b\"]",
                    b"app-server",
                    b"",
                ],
                vec![b"".as_slice(), b"", b"argument with spaces", b""],
            ] {
                let record = argument_record(
                    &executable,
                    &expected,
                    b"CIAO_TEST_SECRET=must_not_be_an_argument\0\xff\0",
                );
                assert_eq!(
                    parse_arguments(&record).unwrap(),
                    expected
                        .iter()
                        .map(|value| std::str::from_utf8(value).unwrap().to_string())
                        .collect::<Vec<_>>()
                );
            }
        }
    }

    #[test]
    fn arguments_refuse_incomplete_invalid_or_oversized_kernel_records() {
        for header in [-1i32, 0, 257] {
            let mut record = argument_record(b"/x", &[b"codex"], b"");
            record[..4].copy_from_slice(&header.to_ne_bytes());
            assert!(parse_arguments(&record).is_none());
        }
        for malformed in [
            Vec::new(),
            vec![1, 0, 0],
            argument_record(b"", &[b"codex"], b""),
            argument_record(b"\xff", &[b"codex"], b""),
            argument_record(b"/x", &[b"\xff"], b""),
        ] {
            assert!(parse_arguments(&malformed).is_none());
        }
        let mut missing_nul = argument_record(b"/x", &[b"codex"], b"");
        missing_nul.pop();
        assert!(parse_arguments(&missing_nul).is_none());
        let mut bad_padding = argument_record(b"/x", &[b"codex"], b"");
        bad_padding[7] = b'x';
        assert!(parse_arguments(&bad_padding).is_none());
        let mut missing_argument = argument_record(b"/x", &[b"codex"], b"");
        missing_argument[..4].copy_from_slice(&2i32.to_ne_bytes());
        assert!(parse_arguments(&missing_argument).is_none());

        let maximum = vec![b'x'; MAX_ARGUMENT_BYTES - 1];
        assert!(parse_arguments(&argument_record(b"/x", &[&maximum], b"")).is_some());
        let oversized = vec![b'x'; MAX_ARGUMENT_BYTES];
        assert!(parse_arguments(&argument_record(b"/x", &[&oversized], b"")).is_none());
        assert_eq!(
            parse_arguments(&argument_record(
                b"/x",
                &vec![b"".as_slice(); MAX_ARGUMENTS],
                b""
            ))
            .unwrap()
            .len(),
            MAX_ARGUMENTS
        );
        let mut saturated = argument_record(b"/x", &[b"codex"], b"");
        saturated.resize(MAX_KERNEL_ARGUMENT_BYTES, 0);
        assert!(parse_arguments(&saturated).is_none());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_arguments_preserve_empty_argv_zero_and_all_executable_path_alignments() {
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};

        assert!(native_arguments(0).is_none());
        assert!(native_arguments(u32::MAX).is_none());
        let directory =
            std::env::temp_dir().join(format!("ciao-native-argv-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        for length in 1..=8 {
            let executable = directory.join("x".repeat(length));
            std::os::unix::fs::symlink("/bin/sleep", &executable).unwrap();
            let alias = if length % 2 == 0 {
                ""
            } else {
                "sleep with spaces"
            };
            let mut child = Command::new(&executable)
                .arg0(alias)
                .arg("30")
                .env_clear()
                .env("CIAO_TEST_SECRET", "must_not_be_an_argument")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let pid = child.id();
            let arguments = native_arguments(pid);
            child.kill().unwrap();
            child.wait().unwrap();
            std::fs::remove_file(&executable).unwrap();
            assert_eq!(arguments, Some(vec![alias.to_owned(), "30".to_owned()]));
            assert!(native_arguments(pid).is_none());
        }
        std::fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn identity_requires_a_complete_boot_uuid_and_consistent_unique_id() {
        let boot = b"12345678-1234-1234-1234-123456789ABC\0";
        let identity = identity_from_records(boot, 12345, 12345).unwrap();
        assert_eq!(identity, "macos:12345678-1234-1234-1234-123456789abc:12345");
        assert_ne!(
            Some(identity.clone()),
            identity_from_records(boot, 12346, 12346)
        );
        assert_ne!(
            Some(identity),
            identity_from_records(b"12345678-1234-1234-1234-123456789ABD\0", 12345, 12345)
        );
        assert!(identity_from_records(boot, 12345, 12346).is_none());
        assert!(identity_from_records(boot, 0, 0).is_none());
        for malformed in [
            b"".as_slice(),
            b"12345678-1234-1234-1234-123456789ABC",
            b"12345678-1234-1234-1234-123456789ABC\n",
            b"12345678-1234-1234-1234-123456789ABG\0",
            b"12345678-1234-1234-1234-123456789ABC\0\0",
            b"12345678-1234-1234-1234-123456789AB\0\0",
        ] {
            assert!(identity_from_records(malformed, 1, 1).is_none());
        }
        assert_eq!(
            identity_from_records(boot, u64::MAX, u64::MAX)
                .unwrap()
                .len(),
            63
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_identity_is_stable_distinguishes_processes_and_disappears_after_exit() {
        use std::process::{Command, Stdio};

        assert!(native_identity(0).is_none());
        assert!(native_identity(u32::MAX).is_none());
        let own = native_identity(std::process::id()).expect("the kernel identifies this process");
        assert_eq!(native_identity(std::process::id()), Some(own.clone()));
        let mut child = Command::new("/bin/sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        let first = native_identity(pid);
        let second = native_identity(pid);
        child.kill().unwrap();
        child.wait().unwrap();
        let first = first.expect("the kernel identifies a live child");
        assert_ne!(
            first, own,
            "simultaneous PIDs have distinct kernel unique IDs"
        );
        assert_eq!(second, Some(first), "a live incarnation stays unchanged");
        assert!(
            native_identity(pid).is_none(),
            "a reaped PID has no kernel identity"
        );
    }
}
