//! Real CLI cancellation with a synthetic npm. No service, registry or user configuration.
use std::{
    fs,
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use nix::{
    sys::signal::{Signal, kill, killpg},
    unistd::Pid,
};

struct OwnedProcesses {
    cli: Child,
    npm: Vec<i32>,
}

impl Drop for OwnedProcesses {
    fn drop(&mut self) {
        if let Some(pid) = self.npm.first() {
            let _ = killpg(Pid::from_raw(*pid), Signal::SIGKILL);
        }
        let _ = killpg(Pid::from_raw(self.cli.id() as i32), Signal::SIGKILL);
        let _ = self.cli.kill();
        let _ = self.cli.wait();
    }
}

fn script(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn exercise(inherited_ignore: bool, interruption: Signal, expected_code: i32) {
    let root = tempfile::Builder::new()
        .prefix("ciao-setup-signal-")
        .tempdir_in("/tmp")
        .unwrap();
    let home = fs::canonicalize(root.path()).unwrap();
    let bin = home.join("bin");
    fs::create_dir(&bin).unwrap();
    let ready = home.join("npm-pids");
    let later = home.join("attached-ran");
    script(&bin.join("node"), "#!/bin/sh\nexit 0\n");
    script(
        &bin.join("claude"),
        "#!/bin/sh\necho reached > \"$TEST_ATTACHED\"\necho 2.1.314\n",
    );
    script(
        &bin.join("npm"),
        "#!/bin/sh\ntrap '' INT TERM\nsleep 60 &\necho \"$$ $!\" > \"$TEST_READY\"\nwait\n",
    );
    // A shell trap gives exec an ignored SIGINT without unsafe pre-exec hooks in the test.
    let mut command = Command::new("/bin/sh");
    command.args([
        "-c",
        if inherited_ignore {
            "trap '' INT; exec \"$@\""
        } else {
            "exec \"$@\""
        },
        "fixture",
        env!("CARGO_BIN_EXE_ciao"),
    ]);
    command
        .args(["agent", "install", "claude"])
        .env_clear()
        .env("HOME", &home)
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .env("TEST_READY", &ready)
        .env("TEST_ATTACHED", &later)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    let mut processes = OwnedProcesses {
        cli: command.spawn().unwrap(),
        npm: Vec::new(),
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(text) = fs::read_to_string(&ready) {
            let pids: Vec<i32> = text
                .split_whitespace()
                .filter_map(|p| p.parse().ok())
                .collect();
            if pids.len() == 2 {
                processes.npm = pids;
                break;
            }
        }
        assert!(Instant::now() < deadline, "fixture npm did not start");
        assert!(
            processes.cli.try_wait().unwrap().is_none(),
            "CLI exited before fixture npm"
        );
        thread::sleep(Duration::from_millis(5));
    }
    // Signal the CLI alone. It must terminate its own npm group, not rely on the terminal
    // delivering another signal to the child or accidentally kill an unrelated daemon.
    kill(Pid::from_raw(processes.cli.id() as i32), interruption).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let status = loop {
        if let Some(status) = processes.cli.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "CLI ignored interruption");
        thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(status.code(), Some(expected_code));
    assert!(
        !later.exists(),
        "cancellation must not run the next component"
    );
    for pid in &processes.npm {
        let deadline = Instant::now() + Duration::from_secs(3);
        while kill(Pid::from_raw(*pid), None).is_ok() {
            // A killed orphan may await init's reaper in minimal Linux test containers.
            #[cfg(target_os = "linux")]
            if fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| {
                s.split_once(") ")
                    .is_some_and(|(_, fields)| fields.starts_with("Z "))
            }) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "npm process {pid} survived cancellation"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }
}

#[test]
fn ctrl_c_at_the_initial_prompt_works_with_one_runtime_worker() {
    use portable_pty::{CommandBuilder, PtySize, native_pty_system};
    let home = tempfile::tempdir().unwrap();
    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .unwrap();
    let mut command = CommandBuilder::new(env!("CARGO_BIN_EXE_ciao"));
    command.env_clear();
    command.env("HOME", home.path());
    command.env("PATH", "/usr/bin:/bin");
    command.env("TOKIO_WORKER_THREADS", "1");
    let mut child = pair.slave.spawn_command(command).unwrap();
    struct Cleanup(Box<dyn portable_pty::ChildKiller + Send + Sync>);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = self.0.kill();
        }
    }
    let _cleanup = Cleanup(child.clone_killer());
    drop(pair.slave);
    let mut reader = pair.master.try_clone_reader().unwrap();
    let mut writer = pair.master.take_writer().unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let mut output = Vec::new();
        let mut byte = [0];
        while reader.read_exact(&mut byte).is_ok() {
            output.push(byte[0]);
            if output.ends_with(b"[Y/n] ") {
                let _ = send.send(());
                break;
            }
        }
    });
    receive
        .recv_timeout(Duration::from_secs(5))
        .expect("setup prompt");
    writer.write_all(b"\x03").unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "prompt swallowed Ctrl-C on a one-worker host"
        );
        thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(status.exit_code(), 130);
}

#[test]
fn ctrl_c_cancels_install_and_its_descendants() {
    exercise(false, Signal::SIGINT, 130);
}

#[test]
fn inherited_ignored_ctrl_c_does_not_make_setup_uncancellable() {
    exercise(true, Signal::SIGINT, 130);
}

#[test]
fn termination_also_cancels_install_and_its_descendants() {
    exercise(false, Signal::SIGTERM, 143);
}
