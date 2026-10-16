//! Compatibility launcher for Firmenstein's existing runtime protocol.
//! All guest initialization and execution live in the GuestWeave library.

use clap::Parser;
use fmst_iib_runtime::execution::{run, ExecLauncher, Intervention, RunConfig, RunError};
use std::ffi::OsString;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "fmst-harness-arm")]
struct Args {
    #[arg(
        long,
        required_unless_present = "trace_only",
        conflicts_with = "trace_only"
    )]
    intervention_so: Option<PathBuf>,
    #[arg(long)]
    trace_only: bool,
    #[arg(long)]
    binary: PathBuf,
    #[arg(long)]
    rootfs: PathBuf,
    #[arg(long)]
    trace_output: Option<PathBuf>,
    #[arg(long)]
    host_loader: Option<PathBuf>,
    #[arg(long)]
    harness_path: Option<PathBuf>,
    #[arg(long)]
    guest_env: Vec<OsString>,
    #[arg(long)]
    guest_unset: Vec<OsString>,
    /// Replacement image's exact argv[0], separate from the ELF pathname.
    #[arg(long)]
    guest_argv0: Option<OsString>,
    #[arg(trailing_var_arg = true)]
    guest_args: Vec<OsString>,
}

fn main() {
    let args = Args::parse();
    let mut config = RunConfig::new(args.binary, args.rootfs);
    config.intervention = match args.intervention_so {
        Some(path) => Intervention::SharedObject(path),
        None => Intervention::None,
    };
    config.args = args.guest_args;
    config.env = args.guest_env;
    config.unset_env = args.guest_unset;
    config.argv0 = args.guest_argv0;
    config.trace_output = args.trace_output;
    config.syscall_trace = true;
    let mut launcher = ExecLauncher::harness(
        args.harness_path
            .unwrap_or_else(|| std::env::current_exe().expect("current harness path")),
    );
    launcher.host_library_path = args
        .host_loader
        .as_ref()
        .map(|_| PathBuf::from("/fmst-host/lib"));
    launcher.host_loader = args.host_loader;
    config.exec = Some(launcher);
    match run(config) {
        Ok(outcome) => log::info!("emulation ended: {}", outcome.shutdown_cause),
        Err(error) => {
            log::error!("{error}");
            let status = match error {
                RunError::Dispatch(_) | RunError::Execution(_) | RunError::UnhandledStop(_) => 3,
                _ => 2,
            };
            std::process::exit(status);
        }
    }
}
