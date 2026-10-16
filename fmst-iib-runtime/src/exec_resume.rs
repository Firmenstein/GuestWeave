//! Private worker bootstrap, separate from the public Intervention ABI and
//! from the existing OFD snapshot. No Rust pointers or heap state are encoded.
use crate::execution::{Intervention, RunConfig};
use serde::{Deserialize, Serialize};
use std::ffi::{CString, OsStr, OsString};
use std::io::{Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub(crate) const ENV: &str = "GUESTWEAVE_EXEC_CONFIG";
// Guest exec strings are already limited to 2 MiB; JSON byte arrays expand
// them by at most four times. Bound the reader too, before decoding anything.
const MAX_BYTES: u64 = 16 * 1024 * 1024;

pub(crate) fn intervention_kind(intervention: &Intervention) -> String {
    match intervention {
        Intervention::None => "none",
        Intervention::Static(_) => "static",
        Intervention::SharedObject(_) => "shared_object",
    }
    .into()
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Resume {
    version: u32,
    pid: u32,
    program: Vec<u8>,
    intervention_kind: String,
    intervention_so: Option<Vec<u8>>,
    binary: Vec<u8>,
    rootfs: Vec<u8>,
    argv: Vec<Vec<u8>>,
    env: Vec<Vec<u8>>,
    unset_env: Vec<Vec<u8>>,
    trace_output: Option<Vec<u8>>,
    syscall_trace: bool,
}

fn bytes(value: &OsStr) -> Vec<u8> {
    value.as_bytes().to_vec()
}

impl Resume {
    pub(crate) fn new(
        config: &crate::module::GuestExecConfig,
        binary: &OsStr,
        argv: &[CString],
        env: &[CString],
        unset_env: &[OsString],
        trace: Option<&Path>,
    ) -> Self {
        Self {
            version: 1,
            pid: std::process::id(),
            program: bytes(config.harness_path.as_os_str()),
            intervention_kind: config.intervention_kind.clone(),
            intervention_so: config
                .intervention_so
                .as_ref()
                .map(|p| bytes(p.as_os_str())),
            binary: bytes(binary),
            rootfs: bytes(config.rootfs.as_os_str()),
            argv: argv.iter().map(|s| s.as_bytes().to_vec()).collect(),
            env: env.iter().map(|s| s.as_bytes().to_vec()).collect(),
            unset_env: unset_env.iter().map(|s| bytes(s)).collect(),
            trace_output: trace.map(|p| bytes(p.as_os_str())),
            syscall_trace: config.syscall_trace,
        }
    }

    pub(crate) fn write(&self, path: &Path) -> Result<(), String> {
        let encoded = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        if encoded.len() as u64 > MAX_BYTES {
            return Err("worker launch handoff exceeds size limit".into());
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("create worker launch handoff: {e}"))?;
        file.write_all(&encoded)
            .map_err(|e| format!("write worker launch handoff: {e}"))
    }

    fn apply(self, config: &mut RunConfig) -> Result<(), String> {
        let launcher = config
            .exec
            .as_ref()
            .filter(|e| e.worker_args.is_some())
            .ok_or("worker launch handoff requires current_process launcher")?;
        if self.version != 1
            || self.pid != std::process::id()
            || self.program != bytes(launcher.program.as_os_str())
            || self.intervention_kind != intervention_kind(&config.intervention)
        {
            return Err("worker launch handoff version/process/intervention mismatch".into());
        }
        match (&mut config.intervention, self.intervention_so) {
            (Intervention::SharedObject(path), Some(value)) => {
                *path = OsString::from_vec(value).into()
            }
            (Intervention::None | Intervention::Static(_), None) => {}
            _ => return Err("worker launch handoff plugin mismatch".into()),
        }
        config.binary = OsString::from_vec(self.binary).into();
        config.rootfs = OsString::from_vec(self.rootfs).into();
        let mut argv = self.argv.into_iter().map(OsString::from_vec);
        config.argv0 = argv.next();
        config.args = argv.collect();
        config.env = self.env.into_iter().map(OsString::from_vec).collect();
        config.unset_env = self.unset_env.into_iter().map(OsString::from_vec).collect();
        config.trace_output = self.trace_output.map(|s| OsString::from_vec(s).into());
        config.syscall_trace = self.syscall_trace;
        Ok(())
    }
}

pub(crate) fn restore(config: &mut RunConfig) -> Result<(), String> {
    let Some(path) = std::env::var_os(ENV) else {
        return Ok(());
    };
    // Remove the host-only transport before QEMU takes an environment copy.
    std::env::remove_var(ENV);
    let path = PathBuf::from(path);
    let mut encoded = Vec::new();
    std::fs::File::open(&path)
        .map_err(|e| format!("open worker launch handoff: {e}"))?
        .take(MAX_BYTES + 1)
        .read_to_end(&mut encoded)
        .map_err(|e| format!("read worker launch handoff: {e}"))?;
    if encoded.len() as u64 > MAX_BYTES {
        return Err("worker launch handoff exceeds size limit".into());
    }
    let resume: Resume = serde_json::from_slice(&encoded)
        .map_err(|e| format!("decode worker launch handoff: {e}"))?;
    let retain = resume.trace_output.is_some();
    resume.apply(config)?;
    // With a trace, retain the exact launch input alongside the OFD evidence.
    if !retain {
        std::fs::remove_file(path).map_err(|e| format!("remove worker launch handoff: {e}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::ExecLauncher;

    fn fixture() -> (Resume, RunConfig) {
        let mut config = RunConfig::new("/old", "/old-root");
        config.exec = Some(ExecLauncher::current_process().unwrap());
        let resume = Resume {
            version: 1,
            pid: std::process::id(),
            program: bytes(config.exec.as_ref().unwrap().program.as_os_str()),
            intervention_kind: "none".into(),
            intervention_so: None,
            binary: b"/next\xff".to_vec(),
            rootfs: b"/root\xfe".to_vec(),
            argv: vec![b"-name,\xff".to_vec(), b"arg,\xfe".to_vec()],
            env: vec![b"KEY=a,\xff".to_vec()],
            unset_env: vec![b"OLD".to_vec()],
            trace_output: Some(b"/trace\xff".to_vec()),
            syscall_trace: true,
        };
        (resume, config)
    }

    #[test]
    fn byte_preserving_resume_and_empty_environment() {
        let (resume, mut config) = fixture();
        let encoded = serde_json::to_vec(&resume).unwrap();
        serde_json::from_slice::<Resume>(&encoded)
            .unwrap()
            .apply(&mut config)
            .unwrap();
        assert_eq!(config.binary.as_os_str().as_bytes(), b"/next\xff");
        assert_eq!(config.argv0.unwrap().as_bytes(), b"-name,\xff");
        assert_eq!(config.args[0].as_bytes(), b"arg,\xfe");
        assert_eq!(config.env[0].as_bytes(), b"KEY=a,\xff");
        let (mut resume, mut config) = fixture();
        resume.env.clear();
        resume.apply(&mut config).unwrap();
        assert!(config.env.is_empty());
        assert_eq!(config.unset_env, vec![OsString::from("OLD")]);
    }

    #[test]
    fn rejects_stale_or_wrong_worker_before_mutating_config() {
        for field in ["version", "pid", "program", "kind"] {
            let (mut resume, mut config) = fixture();
            match field {
                "version" => resume.version += 1,
                "pid" => resume.pid = 0,
                "program" => resume.program = b"different".to_vec(),
                _ => resume.intervention_kind = "static".into(),
            }
            assert!(resume.apply(&mut config).is_err());
            assert_eq!(config.binary, PathBuf::from("/old"));
        }
    }
}
