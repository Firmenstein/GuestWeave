//! Harness diagnostics are host evidence, never guest stdio. The C FILE cookie
//! also captures QEMU's stderr and default qemu_log destination without holding
//! a descriptor while the guest runs. Forks select their own PID path; exec
//! installs a new image sink. This is not a general multithreaded fd namespace.

use std::ffi::{CString, OsString};
use std::io::{self, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

unsafe extern "C" {
    fn fmst_diagnostics_install(prefix: *const libc::c_char) -> libc::c_int;
    fn fmst_diagnostics_write(data: *const libc::c_char, length: usize) -> isize;
    fn fmst_diagnostics_counters(bytes: *mut u64, errors: *mut u64, error: *mut i32);
}

struct Destination {
    prefix: PathBuf,
    binary: PathBuf,
    trace: Option<PathBuf>,
    origin_pid: u32,
    installed_unix_ns: u128,
    requested_qemu_filename: Option<OsString>,
}
static DESTINATION: OnceLock<Destination> = OnceLock::new();

struct DiagnosticWriter;
impl Write for DiagnosticWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let result = unsafe { fmst_diagnostics_write(bytes.as_ptr().cast(), bytes.len()) };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result as usize)
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Install before QEMU or intervention initialization. When no trace path is
/// supplied, use a dedicated temporary directory and announce it before guest
/// execution. Failure is fatal to startup, never a fallback into guest stderr.
pub fn install(binary: &Path, trace: Option<&Path>) -> io::Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let directory = match trace.and_then(Path::parent) {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_owned(),
        _ => std::env::temp_dir().join(format!("fmst-diagnostics-{}-{now}", std::process::id())),
    };
    std::fs::create_dir_all(&directory)?;
    let directory = directory.canonicalize()?;
    if trace.is_none() && std::env::var_os("FMST_EXEC_DEPTH").is_none() {
        eprintln!("Harness diagnostics directory: {}", directory.display());
    }
    let prefix = directory.join(format!("diagnostics-{now}-pid-"));
    let c_prefix = CString::new(prefix.as_os_str().as_bytes())?;
    if unsafe { fmst_diagnostics_install(c_prefix.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let requested_qemu_filename = std::env::var_os("QEMU_LOG_FILENAME");
    // QEMU's -D file would reintroduce a long-lived, guest-closeable fd. Keep
    // QEMU_LOG categories, but own their destination for the whole attempt.
    std::env::remove_var("QEMU_LOG_FILENAME");
    DESTINATION
        .set(Destination {
            prefix,
            binary: binary.to_owned(),
            trace: trace.map(Path::to_owned),
            origin_pid: std::process::id(),
            installed_unix_ns: now,
            requested_qemu_filename,
        })
        .map_err(|_| io::Error::other("diagnostic sink already installed"))?;
    env_logger::Builder::from_default_env()
        .target(env_logger::Target::Pipe(Box::new(DiagnosticWriter)))
        .try_init()
        .map_err(io::Error::other)?;
    // Rust's default panic hook bypasses C stderr and writes to guest fd 2.
    std::panic::set_hook(Box::new(|info| {
        let _ = writeln!(DiagnosticWriter, "harness panic: {info}");
        let _ = checkpoint();
    }));
    checkpoint()?;
    Ok(())
}

/// Guest environment staging must not reactivate QEMU's host file logger.
/// Preserve the variable for the guest through -E, separate from QEMU's own
/// environment lookup. An explicit guest unset still takes precedence.
pub fn guest_filename_argument(inherit: bool, unset: &[OsString]) -> Option<Vec<u8>> {
    let filename = std::env::var_os("QEMU_LOG_FILENAME").or_else(|| {
        inherit
            .then(|| DESTINATION.get()?.requested_qemu_filename.clone())
            .flatten()
    });
    std::env::remove_var("QEMU_LOG_FILENAME");
    if unset.iter().any(|value| value == "QEMU_LOG_FILENAME") {
        return None;
    }
    filename.map(|value| {
        let mut argument = b"QEMU_LOG_FILENAME=".to_vec();
        argument.extend_from_slice(value.as_os_str().as_bytes());
        argument
    })
}

/// Snapshot counters and identity alongside the full log. A missing final
/// checkpoint does not imply complete logging. Fork counters include the
/// inherited prefix and are labelled as such; log files themselves are per PID.
pub fn checkpoint() -> io::Result<()> {
    let Some(destination) = DESTINATION.get() else {
        return Ok(());
    };
    let pid = std::process::id();
    let mut filename = destination.prefix.as_os_str().to_os_string();
    filename.push(format!("{pid}.log"));
    let log_path = PathBuf::from(filename);
    let mut bytes = 0;
    let mut errors = 0;
    let mut last_error = 0;
    unsafe { fmst_diagnostics_counters(&mut bytes, &mut errors, &mut last_error) };
    let stat = std::fs::read_to_string("/proc/self/stat");
    let start_ticks = stat
        .as_ref()
        .ok()
        .and_then(|s| s.rsplit_once(") "))
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .and_then(|v| v.parse::<u64>().ok());
    let stdio: Vec<_> = (0..3)
        .map(
            |fd| match std::fs::read_link(format!("/proc/self/fd/{fd}")) {
                Ok(path) => serde_json::json!({
                    "fd":fd,"target":path,
                    "local_socket":socket_address(fd, false),
                    "peer_socket":socket_address(fd, true),
                }),
                Err(error) => serde_json::json!({"fd":fd,"error":error.to_string()}),
            },
        )
        .collect();
    let trace_path = destination.trace.as_ref().map(|path| {
        if pid == destination.origin_pid {
            path.clone()
        } else {
            path.with_file_name(format!("runtime_trace.pid-{pid}.json"))
        }
    });
    let snapshot = serde_json::json!({
        "schema_version": 2, "kind": "host_diagnostics", "pid_namespace": "harness_container",
        "pid":pid, "parent_pid":unsafe { libc::getppid() }, "process_start_ticks":start_ticks,
        "process_identity_error":stat.err().map(|e| e.to_string()),
        "origin_pid":destination.origin_pid, "image_started_unix_ns":destination.installed_unix_ns,
        "checkpoint_unix_ns":SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos(),
        "binary":destination.binary, "trace_path":trace_path, "log_path":log_path,
        "exec_transition":std::env::var_os("FMST_EXEC_TRANSITION").map(|value| value.to_string_lossy().into_owned()),
        "exec_transition_bytes_hex":std::env::var_os("FMST_EXEC_TRANSITION").map(|value| {
            value.as_os_str().as_bytes().iter().map(|byte| format!("{byte:02x}")).collect::<String>()
        }),
        "stdio_at_checkpoint":stdio,
        "written_bytes_including_fork_prefix":bytes, "write_failures_including_fork_prefix":errors,
        "last_write_errno":last_error, "truncated":false,
        "requested_qemu_log_filename":destination.requested_qemu_filename,
        "collection_complete":false,
        "limitations":["Checkpoint counters are not a terminal receipt.",
            "Transient file writes are not isolated from concurrent guest fd-table mutations."]
    });
    let path = log_path.with_extension("json");
    let temporary = path.with_extension("json.tmp");
    std::fs::write(&temporary, serde_json::to_vec_pretty(&snapshot)?)?;
    std::fs::rename(temporary, path)
}

fn socket_address(fd: libc::c_int, peer: bool) -> Option<serde_json::Value> {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let result = unsafe {
        let address = (&raw mut storage).cast::<libc::sockaddr>();
        if peer {
            libc::getpeername(fd, address, &mut length)
        } else {
            libc::getsockname(fd, address, &mut length)
        }
    };
    if result != 0 {
        return None;
    }
    match storage.ss_family as libc::c_int {
        libc::AF_INET if length as usize >= std::mem::size_of::<libc::sockaddr_in>() => {
            let ipv4 = unsafe {
                (&raw const storage)
                    .cast::<libc::sockaddr_in>()
                    .read_unaligned()
            };
            Some(serde_json::json!({
                "family":"ipv4", "address":Ipv4Addr::from(u32::from_be(ipv4.sin_addr.s_addr)),
                "port":u16::from_be(ipv4.sin_port),
            }))
        }
        libc::AF_INET6 if length as usize >= std::mem::size_of::<libc::sockaddr_in6>() => {
            let ipv6 = unsafe {
                (&raw const storage)
                    .cast::<libc::sockaddr_in6>()
                    .read_unaligned()
            };
            Some(serde_json::json!({
                "family":"ipv6", "address":Ipv6Addr::from(ipv6.sin6_addr.s6_addr),
                "port":u16::from_be(ipv6.sin6_port),
            }))
        }
        _ => None,
    }
}
