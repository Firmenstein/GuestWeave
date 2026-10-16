use std::{
    fs,
    process::Command,
    time::{Duration, Instant},
};

include!(concat!(env!("OUT_DIR"), "/demo-bindings.rs"));

#[test]
fn linked_intervention_runs_guest_and_persists_mapped_trace() {
    let requested_output = std::env::var_os("GUESTWEAVE_TEST_OUTPUT");
    // Keep evidence on assertion failure, including in the default test path.
    let directory = requested_output
        .clone()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| tempfile::tempdir().unwrap().keep());
    fs::create_dir_all(&directory).unwrap();
    let trace_path = directory.join("trace.json");
    // Timeout includes the actual worker; on expiry kill and reap it.
    let stdout = fs::File::create(directory.join("guest.stdout")).unwrap();
    let stderr = fs::File::create(directory.join("guest.stderr")).unwrap();
    let mut worker = Command::new(env!("CARGO_BIN_EXE_guestweave-embedded-example"))
        .arg(&trace_path)
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = worker.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            worker.kill().unwrap();
            worker.wait().unwrap();
            panic!(
                "guest did not exit within 20 seconds; evidence at {}",
                directory.display()
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(
        status.success(),
        "guest exit {status}; evidence at {}",
        directory.display()
    );
    assert_eq!(
        fs::read(directory.join("guest.stdout")).unwrap(),
        b"embedded-guest-ok\n"
    );
    assert!(fs::read(directory.join("guest.stderr")).unwrap().is_empty());
    let trace: serde_json::Value = serde_json::from_slice(&fs::read(trace_path).unwrap()).unwrap();
    assert_eq!(trace["guest_arch"], env!("GUESTWEAVE_GUEST_ARCH"));
    assert!(trace["total_block_executions"].as_u64().unwrap() > 0);
    let image = trace["image_loads"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["detail"].as_str().unwrap().starts_with("demo-guest@"))
        .unwrap();
    let base = u64::from_str_radix(
        image["detail"]
            .as_str()
            .unwrap()
            .split('@')
            .nth(1)
            .unwrap()
            .trim_start_matches("0x"),
        16,
    )
    .unwrap();
    let events = trace["events"].as_array().unwrap();
    let hook = events.iter().find(|e| e["kind"] == "iib_hook").unwrap();
    assert_eq!(hook["pc"].as_u64(), Some(base + CALL_OFFSET));
    assert!(trace["blocks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|b| b["pc"].as_u64() == Some(base + RESUME_OFFSET)));
    assert!(events.iter().any(|e| e["kind"] == "guest_exec_disabled"));
    assert!(trace["terminal_reason"]
        .as_str()
        .unwrap()
        .starts_with("process_exit:"));
    if requested_output.is_none() {
        fs::remove_dir_all(directory).unwrap();
    }
}

#[test]
fn linked_worker_reenters_after_direct_and_fork_exec() {
    use std::os::unix::process::CommandExt;
    unsafe extern "C" {
        fn kill(pid: i32, signal: i32) -> i32;
    }
    for mode in ["direct", "fork", "empty"] {
        let requested = std::env::var_os("GUESTWEAVE_TEST_OUTPUT");
        let directory = requested
            .as_ref()
            .map(std::path::PathBuf::from)
            .map(|p| p.join(mode))
            .unwrap_or_else(|| tempfile::tempdir().unwrap().keep());
        fs::create_dir_all(&directory).unwrap();
        let mut worker = Command::new(env!("CARGO_BIN_EXE_guestweave-embedded-example"))
            .current_dir(&directory)
            .arg("trace.json")
            .arg(mode)
            .stdout(fs::File::create(directory.join("guest.stdout")).unwrap())
            .stderr(fs::File::create(directory.join("guest.stderr")).unwrap())
            .process_group(0)
            .spawn()
            .unwrap();
        let group = worker.id() as i32;
        let deadline = Instant::now() + Duration::from_secs(20);
        let status = loop {
            if let Some(status) = worker.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                unsafe {
                    kill(-group, 9);
                }
                worker.wait().unwrap();
                panic!("{mode} timed out; evidence at {}", directory.display());
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        unsafe {
            kill(-group, 9);
        }
        assert!(
            status.success(),
            "{mode}: {status}; evidence at {}",
            directory.display()
        );
        assert_eq!(
            fs::read(directory.join("guest.stdout")).unwrap(),
            b"embedded-exec-ok\n"
        );
        assert!(fs::read(directory.join("guest.stderr")).unwrap().is_empty());
        let artifacts: Vec<serde_json::Value> = fs::read_dir(&directory)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "json"))
            .map(|p| serde_json::from_slice(&fs::read(p).unwrap()).unwrap())
            .collect();
        let transitions: Vec<_> = artifacts
            .iter()
            .filter(|a| a.get("transition_id").is_some())
            .collect();
        let exec_count = if mode == "empty" { 1 } else { 2 };
        assert_eq!(transitions.len(), exec_count);
        for transition in &transitions {
            assert_eq!(transition["status"], "started");
            assert!(
                std::path::Path::new(transition["worker_launch_handoff"].as_str().unwrap())
                    .is_file()
            );
        }
        let restored = artifacts
            .iter()
            .filter_map(|a| a["events"].as_array())
            .flatten()
            .any(|event| {
                event["kind"] == "virtual_fd_exec_handoff_restored"
                    && event["detail"].as_str().unwrap().contains("descriptors=2")
            });
        assert!(restored, "OFD handoff was not restored");
        let image_hook_count = artifacts
            .iter()
            .filter(|a| {
                a["events"]
                    .as_array()
                    .is_some_and(|events| events.iter().any(|e| e["kind"] == "iib_hook"))
            })
            .count();
        assert!(
            image_hook_count > exec_count,
            "hook missing in replacement image trace"
        );
        if requested.is_none() {
            fs::remove_dir_all(directory).unwrap();
        }
    }
}
