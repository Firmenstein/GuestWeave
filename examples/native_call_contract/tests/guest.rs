use std::{
    fs,
    process::Command,
    time::{Duration, Instant},
};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[test]
fn native_call_contract_runs_all_modes() {
    let requested = std::env::var_os("GUESTWEAVE_TEST_OUTPUT");
    let root = requested
        .as_ref()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| tempfile::tempdir().unwrap().keep());
    fs::create_dir_all(&root).unwrap();
    let root = root.canonicalize().unwrap();
    fs::copy(env!("PROBE_GUEST"), root.join("probe-guest")).unwrap();
    fs::write(
        root.join("bindings.rs"),
        include_str!(concat!(env!("OUT_DIR"), "/bindings.rs")),
    )
    .unwrap();
    fs::write(
        root.join("elf-identity.txt"),
        include_str!(concat!(env!("OUT_DIR"), "/elf-identity.txt")),
    )
    .unwrap();
    let expected = [
        (40, 1, 1),
        (900, 3, 0),
        (41, 2, 1),
        (601, 2, 0),
        (602, 2, 0),
        (603, 1, 1),
    ];
    for (mode, (result, hooks, bodies)) in expected.into_iter().enumerate() {
        let evidence = root.join(format!("mode-{mode}"));
        fs::create_dir_all(&evidence).unwrap();
        let trace = evidence.join("trace.json");
        let mut worker = Command::new(env!("CARGO_BIN_EXE_guestweave-native-call-contract"))
            .current_dir(&evidence)
            .arg(root.join("probe-guest"))
            .arg(&trace)
            .arg(mode.to_string())
            .stdout(fs::File::create(evidence.join("guest.stdout")).unwrap())
            .stderr(fs::File::create(evidence.join("guest.stderr")).unwrap())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = worker.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                worker.kill().unwrap();
                worker.wait().unwrap();
                panic!("mode {mode} timed out; evidence at {}", evidence.display());
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(
            status.success(),
            "mode {mode} exited {status}; evidence at {}",
            evidence.display()
        );
        let expected_stdout =
            format!("mode={mode} result={result} hooks={hooks} bodies={bodies}\n")
                + "native-call-contract-ok\n";
        assert_eq!(
            fs::read_to_string(evidence.join("guest.stdout")).unwrap(),
            expected_stdout,
            "mode {mode}; evidence at {}",
            evidence.display()
        );
        let trace: serde_json::Value = serde_json::from_slice(&fs::read(&trace).unwrap()).unwrap();
        assert_eq!(trace["guest_arch"], env!("GUESTWEAVE_GUEST_ARCH"));
        assert!(trace["total_block_executions"].as_u64().unwrap() > 0);
        assert!(trace["terminal_reason"]
            .as_str()
            .unwrap()
            .starts_with("process_exit:"));
        let events = trace["events"].as_array().unwrap();
        let hook_events: Vec<_> = events.iter().filter(|e| e["kind"] == "iib_hook").collect();
        assert_eq!(hook_events.len(), hooks as usize);
        let failures = events
            .iter()
            .filter(|event| event["kind"] == "native_call_resolution_failed")
            .count();
        assert_eq!(failures, usize::from(mode == 4));
        let images = trace["image_loads"].as_array().unwrap();
        let image = images
            .iter()
            .find(|event| {
                event["detail"]
                    .as_str()
                    .unwrap()
                    .starts_with("probe-guest@")
            })
            .expect("probe image load");
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
        assert_eq!(base, ELF_MAP_BASE);
        assert!(hook_events
            .iter()
            .all(|event| event["pc"] == base + PROBE_OFFSET));
        assert!(hook_events.iter().all(|event| event["pc"] == PROBE_LINK_VA));
    }
    if requested.is_none() {
        fs::remove_dir_all(&root).unwrap();
    }
}
