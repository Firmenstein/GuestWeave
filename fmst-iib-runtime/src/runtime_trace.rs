//! Bounded runtime evidence for Runner-driven rehosting refinement.
//!
//! The trace is deliberately not an instruction log. It keeps saturated hit
//! counts for a bounded set of translated basic blocks, a short run-length
//! encoded execution tail, and low-volume IIB events. Periodic atomic
//! checkpoints preserve useful evidence when an external timeout kills QEMU.

use libafl_qemu::modules::{EmulatorModule, EmulatorModuleTuple};
use libafl_qemu::{EmulatorModules, GuestAddr, GuestUlong, Hook, Qemu, SyscallHookResult};
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicPtr, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DEFAULT_MAX_UNIQUE_BLOCKS: usize = 100_000;
const DEFAULT_TAIL_ENTRIES: usize = 256;
const DEFAULT_FOCUS_TAIL_ENTRIES: usize = 512;
const DEFAULT_MAX_EVENTS: usize = 1_024;
const DEFAULT_CHECKPOINT_INTERVAL: u64 = 65_536;
const MIN_CHECKPOINT_INTERVAL: Duration = Duration::from_millis(250);

static GLOBAL_TRACE_MODULE_PTR: AtomicPtr<RuntimeTraceModule> =
    AtomicPtr::new(std::ptr::null_mut());

#[derive(Debug, Serialize)]
struct BlockHit {
    pc: u64,
    hit_count: u32,
}

#[derive(Clone, Debug, Serialize)]
struct TailEntry {
    pc: u64,
    consecutive_hits: u32,
}

#[derive(Clone, Debug, Serialize)]
struct RuntimeEvent {
    sequence: u64,
    last_sequence: u64,
    repeat_count: u64,
    kind: String,
    detail: String,
    pc: Option<u64>,
    registers: Vec<RegisterValue>,
    memory: Vec<MemorySnapshot>,
    elapsed_ns: u64,
    last_elapsed_ns: u64,
    detail_dropped_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct RegisterValue {
    name: &'static str,
    value: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct MemorySnapshot {
    address: u64,
    requested_bytes: usize,
    source_register: &'static str,
    bytes: Vec<u8>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct RuntimeTraceSnapshot {
    schema_version: u32,
    guest_arch: &'static str,
    byte_order: &'static str,
    word_bits: u8,
    host_pid: u32,
    origin_pid: u32,
    started_unix_ns: u64,
    checkpoint_elapsed_ns: u64,
    terminal_reason: Option<String>,
    dropped_events: u64,
    dropped_image_loads: u64,
    dropped_tail_entries: u64,
    dropped_focus_tail_entries: u64,
    image_loads: Vec<RuntimeEvent>,
    main_load_address: u64,
    total_block_executions: u64,
    observed_unique_blocks: usize,
    dropped_unique_blocks: u64,
    blocks: Vec<BlockHit>,
    recent_blocks: Vec<TailEntry>,
    focus_images: Vec<String>,
    recent_focus_blocks: Vec<TailEntry>,
    events: Vec<RuntimeEvent>,
}

#[derive(Debug, Serialize)]
struct RuntimeTraceHeartbeat {
    schema_version: u32,
    origin_pid: u32,
    checkpoint_elapsed_ns: u64,
    total_block_executions: u64,
    observed_unique_blocks: usize,
    last_pc: Option<u64>,
    last_event_sequence: u64,
    terminal_reason: Option<String>,
}

#[derive(Debug)]
pub struct RuntimeTraceModule {
    started: Instant,
    started_unix_ns: u64,
    origin_pid: u32,
    terminal_reason: Option<String>,
    dropped_events: u64,
    dropped_image_loads: u64,
    dropped_tail_entries: u64,
    dropped_focus_tail_entries: u64,
    image_loads: Vec<RuntimeEvent>,
    output_path: Option<PathBuf>,
    block_hits: HashMap<u64, u32>,
    tail: VecDeque<TailEntry>,
    focus_images: Vec<String>,
    focus_ranges: Vec<(u64, u64)>,
    focus_tail: VecDeque<TailEntry>,
    events: VecDeque<RuntimeEvent>,
    total_block_executions: u64,
    dropped_unique_blocks: u64,
    next_event_sequence: u64,
    max_unique_blocks: usize,
    max_tail_entries: usize,
    max_focus_tail_entries: usize,
    max_events: usize,
    checkpoint_interval: u64,
    last_checkpoint: Instant,
    main_load_address: u64,
    exit_syscalls: Vec<i32>,
    first_stdio_events: HashSet<(u32, i32, i32)>,
    fork_checkpoint_pid: Option<u32>,
}

impl RuntimeTraceModule {
    pub fn new(output_path: PathBuf) -> Self {
        Self {
            started: Instant::now(),
            started_unix_ns: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
                .min(u64::MAX as u128) as u64,
            origin_pid: std::process::id(),
            first_stdio_events: HashSet::new(),
            fork_checkpoint_pid: None,
            terminal_reason: None,
            dropped_events: 0,
            dropped_image_loads: 0,
            dropped_tail_entries: 0,
            dropped_focus_tail_entries: 0,
            image_loads: Vec::new(),
            output_path: Some(output_path),
            block_hits: HashMap::new(),
            tail: VecDeque::new(),
            focus_images: Vec::new(),
            focus_ranges: Vec::new(),
            focus_tail: VecDeque::new(),
            events: VecDeque::new(),
            total_block_executions: 0,
            dropped_unique_blocks: 0,
            next_event_sequence: 0,
            max_unique_blocks: DEFAULT_MAX_UNIQUE_BLOCKS,
            max_tail_entries: DEFAULT_TAIL_ENTRIES,
            max_focus_tail_entries: DEFAULT_FOCUS_TAIL_ENTRIES,
            max_events: DEFAULT_MAX_EVENTS,
            checkpoint_interval: DEFAULT_CHECKPOINT_INTERVAL,
            last_checkpoint: Instant::now(),
            main_load_address: 0,
            exit_syscalls: Vec::new(),
        }
    }

    pub fn with_exit_syscalls(mut self, exit_syscalls: &[i32]) -> Self {
        self.exit_syscalls = exit_syscalls.to_vec();
        self
    }

    pub fn disabled() -> Self {
        let mut module = Self::new(PathBuf::new());
        module.output_path = None;
        module
    }

    fn observe_block(&mut self, pc: u64) {
        let pid = std::process::id();
        if pid != self.origin_pid && self.fork_checkpoint_pid != Some(pid) {
            self.fork_checkpoint_pid = Some(pid);
            self.push_event("fork_child", format!("pid={pid}; origin_pid={}", self.origin_pid));
            // A child can signal before its first syscall or the ordinary
            // checkpoint interval. Persist its own identity before that block.
            self.checkpoint_if_due(true);
        }
        self.total_block_executions = self.total_block_executions.saturating_add(1);
        if let Some(count) = self.block_hits.get_mut(&pc) {
            *count = count.saturating_add(1);
        } else if self.block_hits.len() < self.max_unique_blocks {
            self.block_hits.insert(pc, 1);
        } else {
            self.dropped_unique_blocks = self.dropped_unique_blocks.saturating_add(1);
        }

        self.dropped_tail_entries += push_tail(&mut self.tail, pc, self.max_tail_entries);
        if self
            .focus_ranges
            .iter()
            .any(|&(start, end)| start <= pc && pc < end)
        {
            self.dropped_focus_tail_entries +=
                push_tail(&mut self.focus_tail, pc, self.max_focus_tail_entries);
        }

        if self.total_block_executions == 256
            || self.total_block_executions % self.checkpoint_interval == 0
        {
            self.checkpoint_if_due(self.total_block_executions == 256);
        }
    }

    fn push_event(&mut self, kind: &str, detail: String) {
        self.push_event_with_state(kind, detail, None, Vec::new(), Vec::new());
    }

    fn push_event_with_state(
        &mut self,
        kind: &str,
        detail: String,
        pc: Option<u64>,
        registers: Vec<RegisterValue>,
        memory: Vec<MemorySnapshot>,
    ) {
        let elapsed_ns = self.started.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        let mut end = detail.len().min(4096);
        while !detail.is_char_boundary(end) {
            end -= 1;
        }
        let detail_dropped_bytes = detail.len() - end;
        let detail = detail[..end].to_owned();
        if matches!(
            kind,
            "qemu_end" | "qemu_error" | "iib_callsite_error" | "process_exit"
        ) {
            self.terminal_reason = Some(format!("{kind}: {detail}"));
        }
        self.next_event_sequence = self.next_event_sequence.saturating_add(1);
        if let Some(last) = self.events.back_mut() {
            if last.kind == kind
                && last.detail == detail
                && last.pc == pc
                && last.registers == registers
                && last.memory == memory
                && detail_dropped_bytes == 0
                && last.detail_dropped_bytes == 0
            {
                last.last_sequence = self.next_event_sequence;
                last.repeat_count = last.repeat_count.saturating_add(1);
                last.last_elapsed_ns = elapsed_ns;
                return;
            }
        }
        self.events.push_back(RuntimeEvent {
            sequence: self.next_event_sequence,
            last_sequence: self.next_event_sequence,
            repeat_count: 1,
            kind: kind.to_owned(),
            detail,
            pc,
            registers,
            memory,
            elapsed_ns,
            last_elapsed_ns: elapsed_ns,
            detail_dropped_bytes,
        });
        // Load identity must outlive the event ring. This is bounded by the
        // number of actual loaded images, not by the runtime duration.
        if kind == "image_load" {
            if self.image_loads.len() < 1024 {
                self.image_loads.push(self.events.back().unwrap().clone());
            } else {
                self.dropped_image_loads += 1;
            }
        }
        while self.events.len() > self.max_events {
            if let Some(event) = self.events.pop_front() {
                self.dropped_events = self.dropped_events.saturating_add(event.repeat_count);
            }
        }
    }

    pub fn flush(&self) -> std::io::Result<()> {
        if let Err(error) = crate::diagnostics::checkpoint() {
            log::warn!("diagnostic checkpoint failed: {error}");
        }
        let Some(output_path) = self.output_path.as_ref() else {
            return Ok(());
        };
        let mut blocks: Vec<BlockHit> = self
            .block_hits
            .iter()
            .map(|(&pc, &hit_count)| BlockHit { pc, hit_count })
            .collect();
        blocks.sort_by_key(|item| item.pc);
        let snapshot = RuntimeTraceSnapshot {
            schema_version: 6,
            guest_arch: guest_arch_name(),
            byte_order: if cfg!(feature = "mipsbe") {
                "big"
            } else {
                "little"
            },
            word_bits: if cfg!(feature = "x86_64") { 64 } else { 32 },
            host_pid: std::process::id(),
            origin_pid: self.origin_pid,
            started_unix_ns: self.started_unix_ns,
            checkpoint_elapsed_ns: self.started.elapsed().as_nanos().min(u64::MAX as u128) as u64,
            terminal_reason: self.terminal_reason.clone(),
            dropped_events: self.dropped_events,
            dropped_image_loads: self.dropped_image_loads,
            dropped_tail_entries: self.dropped_tail_entries,
            dropped_focus_tail_entries: self.dropped_focus_tail_entries,
            image_loads: self.image_loads.clone(),
            main_load_address: self.main_load_address,
            total_block_executions: self.total_block_executions,
            observed_unique_blocks: blocks.len(),
            dropped_unique_blocks: self.dropped_unique_blocks,
            blocks,
            recent_blocks: self.tail.iter().cloned().collect(),
            focus_images: self.focus_images.clone(),
            recent_focus_blocks: self.focus_tail.iter().cloned().collect(),
            events: self.events.iter().cloned().collect(),
        };
        // forked harnesses may share inherited state but never overwrite the
        // parent's checkpoint. The origin PID makes the inherited prefix explicit.
        let fork_path =
            output_path.with_file_name(format!("runtime_trace.pid-{}.json", std::process::id()));
        let output_path = if std::process::id() == self.origin_pid {
            output_path
        } else {
            &fork_path
        };
        if let Some(parent) = output_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let temporary = output_path.with_extension("json.tmp");
        let encoded = serde_json::to_vec_pretty(&snapshot).map_err(std::io::Error::other)?;
        std::fs::write(&temporary, encoded)?;
        std::fs::rename(temporary, output_path)?;
        let heartbeat_path = heartbeat_path(output_path);
        let heartbeat_temporary = heartbeat_path.with_extension("json.tmp");
        let heartbeat = RuntimeTraceHeartbeat {
            schema_version: 1,
            origin_pid: self.origin_pid,
            checkpoint_elapsed_ns: snapshot.checkpoint_elapsed_ns,
            total_block_executions: snapshot.total_block_executions,
            observed_unique_blocks: snapshot.observed_unique_blocks,
            last_pc: self.tail.back().map(|entry| entry.pc),
            last_event_sequence: self
                .events
                .back()
                .map(|event| event.last_sequence)
                .unwrap_or(0),
            terminal_reason: snapshot.terminal_reason.clone(),
        };
        let heartbeat_encoded =
            serde_json::to_vec_pretty(&heartbeat).map_err(std::io::Error::other)?;
        std::fs::write(&heartbeat_temporary, heartbeat_encoded)?;
        std::fs::rename(heartbeat_temporary, heartbeat_path)
    }

    fn checkpoint_if_due(&mut self, force: bool) {
        if !force && self.last_checkpoint.elapsed() < MIN_CHECKPOINT_INTERVAL {
            return;
        }
        if let Err(error) = self.flush() {
            log::warn!("failed to checkpoint runtime trace: {error}");
        } else {
            self.last_checkpoint = Instant::now();
        }
    }
}

fn heartbeat_path(trace_path: &Path) -> PathBuf {
    let stem = trace_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("runtime_trace");
    trace_path.with_file_name(format!("{stem}.heartbeat.json"))
}

fn push_tail(tail: &mut VecDeque<TailEntry>, pc: u64, max_entries: usize) -> u64 {
    if let Some(last) = tail.back_mut() {
        if last.pc == pc {
            last.consecutive_hits = last.consecutive_hits.saturating_add(1);
        } else {
            tail.push_back(TailEntry {
                pc,
                consecutive_hits: 1,
            });
        }
    } else {
        tail.push_back(TailEntry {
            pc,
            consecutive_hits: 1,
        });
    }
    let mut dropped = 0;
    while tail.len() > max_entries {
        tail.pop_front();
        dropped += 1;
    }
    dropped
}

fn guest_arch_name() -> &'static str {
    if cfg!(feature = "arm") {
        "arm"
    } else if cfg!(feature = "mipsbe") {
        "mipsbe"
    } else if cfg!(feature = "mips") {
        "mipsel"
    } else if cfg!(feature = "x86_64") {
        "x86_64"
    } else {
        "unknown"
    }
}

fn gen_block_pc<ET, I, S>(
    _qemu: Qemu,
    _modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    pc: GuestAddr,
) -> Option<u64>
where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin + 'static,
    S: Unpin + 'static,
{
    Some(pc as u64)
}

fn exec_block<ET, I, S>(
    _qemu: Qemu,
    modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    pc: u64,
) where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin + 'static,
    S: Unpin + 'static,
{
    modules
        .get_mut::<RuntimeTraceModule>()
        .expect("RuntimeTraceModule missing")
        .observe_block(pc);
}

#[allow(clippy::too_many_arguments)]
fn trace_exit_syscall<ET, I, S>(
    qemu: Qemu,
    modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    syscall: i32,
    a0: GuestUlong,
    _a1: GuestUlong,
    _a2: GuestUlong,
    _a3: GuestUlong,
    _a4: GuestUlong,
    _a5: GuestUlong,
    _a6: GuestUlong,
    _a7: GuestUlong,
) -> SyscallHookResult
where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin + 'static,
    S: Unpin + 'static,
{
    let trace = modules
        .get_mut::<RuntimeTraceModule>()
        .expect("RuntimeTraceModule missing");
    let exiting = trace.exit_syscalls.contains(&syscall);
    if exiting {
        let (pc, registers, memory) = capture_registers(qemu);
        trace.push_event_with_state(
            "process_exit",
            format!("guest syscall {syscall}; status={a0:#x}"),
            pc,
            registers,
            memory,
        );
    }
    // A service often blocks in accept/poll long before the block-count
    // checkpoint. Persist the latest prefix at syscall boundaries without
    // writing more than four times per second; process exit always flushes.
    trace.checkpoint_if_due(exiting);
    SyscallHookResult::Run
}

fn interesting_syscall_name(syscall: i32) -> Option<&'static str> {
    #[cfg(feature = "arm")]
    let name = match syscall {
        5 => Some("open"),
        54 => Some("ioctl"),
        142 => Some("select"),
        168 => Some("poll"),
        252 => Some("epoll_wait"),
        281 => Some("socket"),
        282 => Some("bind"),
        283 => Some("connect"),
        284 => Some("listen"),
        285 => Some("accept"),
        322 => Some("openat"),
        366 => Some("accept4"),
        _ => None,
    };
    #[cfg(any(feature = "mips", feature = "mipsbe"))]
    let name = match syscall {
        4005 => Some("open"),
        4054 => Some("ioctl"),
        4142 => Some("select"),
        4168 => Some("accept"),
        4169 => Some("bind"),
        4170 => Some("connect"),
        4174 => Some("listen"),
        4183 => Some("socket"),
        4188 => Some("poll"),
        4250 => Some("epoll_wait"),
        4288 => Some("openat"),
        4334 => Some("accept4"),
        _ => None,
    };
    #[cfg(feature = "x86_64")]
    let name = match syscall {
        2 => Some("open"),
        7 => Some("poll"),
        16 => Some("ioctl"),
        23 => Some("select"),
        41 => Some("socket"),
        42 => Some("connect"),
        43 => Some("accept"),
        49 => Some("bind"),
        50 => Some("listen"),
        232 => Some("epoll_wait"),
        257 => Some("openat"),
        288 => Some("accept4"),
        _ => None,
    };
    #[cfg(not(any(
        feature = "arm",
        feature = "mips",
        feature = "mipsbe",
        feature = "x86_64"
    )))]
    let name = None;
    name
}

fn signed_syscall_result(result: GuestUlong) -> i64 {
    #[cfg(feature = "x86_64")]
    return result as i64;
    #[cfg(not(feature = "x86_64"))]
    return (result as u32 as i32) as i64;
}

fn stdio_operation(syscall: i32) -> Option<&'static str> {
    #[cfg(feature = "arm")]
    let operation = match syscall { 3 => Some("read"), 4 => Some("write"), _ => None };
    #[cfg(any(feature = "mips", feature = "mipsbe"))]
    let operation = match syscall { 4003 => Some("read"), 4004 => Some("write"), _ => None };
    #[cfg(feature = "x86_64")]
    let operation = match syscall { 0 => Some("read"), 1 => Some("write"), _ => None };
    #[cfg(not(any(feature = "arm", feature = "mips", feature = "mipsbe", feature = "x86_64")))]
    let operation = None;
    operation
}

#[allow(clippy::too_many_arguments)]
fn trace_interesting_syscall_result<ET, I, S>(
    qemu: Qemu,
    modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    result: GuestUlong,
    syscall: i32,
    a0: GuestUlong,
    a1: GuestUlong,
    a2: GuestUlong,
    a3: GuestUlong,
    _a4: GuestUlong,
    _a5: GuestUlong,
    _a6: GuestUlong,
    _a7: GuestUlong,
) -> GuestUlong
where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin + 'static,
    S: Unpin + 'static,
{
    if let Some(operation) = stdio_operation(syscall) {
        let signed_result = signed_syscall_result(result);
        let fd = a0 as i32;
        if (0..=2).contains(&fd) && signed_result > 0 {
            let trace = modules.get_mut::<RuntimeTraceModule>()
                .expect("RuntimeTraceModule missing");
            if trace.first_stdio_events.insert((std::process::id(), syscall, fd)) {
                let (pc, registers, memory) = capture_registers(qemu);
                trace.push_event_with_state(
                    "stdio_io",
                    format!("operation={operation}; fd={fd}; transferred_bytes={signed_result}"),
                    pc, registers, memory,
                );
                // An exec child can exit or crash before the normal 250 ms
                // checkpoint. Its first actual I/O must be durable now.
                trace.checkpoint_if_due(true);
            }
        }
    }
    if let Some(name) = interesting_syscall_name(syscall) {
        let signed_result = signed_syscall_result(result);
        let (pc, registers, memory) = capture_registers(qemu);
        modules
            .get_mut::<RuntimeTraceModule>()
            .expect("RuntimeTraceModule missing")
                .push_event_with_state(
                "syscall_result",
                format!(
                    "{name}(nr={syscall}, a0={a0:#x}, a1={a1:#x}, a2={a2:#x}, a3={a3:#x}) -> {signed_result}"
                ),
                pc,
                    registers,
                    memory,
            );
    }
    result
}

impl<I, S> EmulatorModule<I, S> for RuntimeTraceModule
where
    I: Unpin + 'static,
    S: Unpin + 'static,
{
    fn post_qemu_init<ET>(&mut self, qemu: Qemu, modules: &mut EmulatorModules<ET, I, S>)
    where
        ET: EmulatorModuleTuple<I, S>,
    {
        if self.output_path.is_none() {
            return;
        }
        self.main_load_address = qemu.load_addr() as u64;
        self.last_checkpoint = Instant::now();
        GLOBAL_TRACE_MODULE_PTR.store(self as *mut _, Ordering::Release);
        modules.blocks(
            Hook::Function(gen_block_pc::<ET, I, S>),
            Hook::Empty,
            Hook::Function(exec_block::<ET, I, S>),
        );
        modules.pre_syscalls(Hook::Function(trace_exit_syscall::<ET, I, S>));
        modules.post_syscalls(Hook::Function(trace_interesting_syscall_result::<ET, I, S>));
        if let Err(error) = self.flush() {
            log::warn!("failed to initialize runtime trace: {error}");
        }
    }
}

/// Add one bounded, structured event to the live trace if tracing is enabled.
pub fn record_runtime_event(kind: &str, detail: impl Into<String>) {
    let ptr = GLOBAL_TRACE_MODULE_PTR.load(Ordering::Acquire);
    if ptr.is_null() {
        return;
    }
    // SAFETY: RuntimeTraceModule is pinned inside EmulatorModules for the
    // process lifetime. QEMU and hook dispatch execute on the same thread.
    unsafe {
        (*ptr).push_event(kind, detail.into());
    }
}

/// Return the process that created the current trace.  QEMU user-mode may
/// fork the harness before a guest child calls `execve`; the inherited trace
/// module then lets the child choose distinct artifact names without claiming
/// that its virtual OFD state is shared with the parent.
pub fn trace_origin_pid() -> Option<u32> {
    let ptr = GLOBAL_TRACE_MODULE_PTR.load(Ordering::Acquire);
    if ptr.is_null() {
        return None;
    }
    // SAFETY: RuntimeTraceModule is pinned inside EmulatorModules for the
    // process lifetime, and this read is immutable.
    unsafe { Some((*ptr).origin_pid) }
}

/// Preserve a second execution tail for the target executable and managed
/// custom libraries.  libc/loader blocks can otherwise evict the exact guest
/// branch that led into a common error or exit path.
pub fn set_runtime_focus_ranges(images: Vec<String>, ranges: Vec<(u64, u64)>) {
    let ptr = GLOBAL_TRACE_MODULE_PTR.load(Ordering::Acquire);
    if ptr.is_null() {
        return;
    }
    unsafe {
        (*ptr).focus_images = images;
        (*ptr).focus_ranges = ranges;
        (*ptr).focus_tail.clear();
    }
}

/// Record a low-volume event with the registers needed to explain its state.
pub fn record_runtime_state_event(kind: &str, detail: impl Into<String>) {
    record_runtime_state_event_at(kind, detail, None);
}

/// Record register state while attributing the event to an explicit source
/// PC. This is used by MIPS callsite hooks after their delay slot has run.
pub fn record_runtime_state_event_at(kind: &str, detail: impl Into<String>, event_pc: Option<u64>) {
    let ptr = GLOBAL_TRACE_MODULE_PTR.load(Ordering::Acquire);
    if ptr.is_null() {
        return;
    }
    let Some(qemu) = Qemu::get() else {
        return;
    };
    let (captured_pc, registers, memory) = capture_registers(qemu);
    unsafe {
        (*ptr).push_event_with_state(
            kind,
            detail.into(),
            event_pc.or(captured_pc),
            registers,
            memory,
        );
    }
}

fn capture_registers(qemu: Qemu) -> (Option<u64>, Vec<RegisterValue>, Vec<MemorySnapshot>) {
    let Some(cpu) = qemu.current_cpu() else {
        return (None, Vec::new(), Vec::new());
    };
    let mut values = Vec::new();
    macro_rules! capture {
        ($name:literal, $reg:expr) => {
            if let Ok(value) = cpu.read_reg($reg) {
                values.push(RegisterValue {
                    name: $name,
                    value: value as u64,
                });
            }
        };
    }
    #[cfg(feature = "arm")]
    {
        use libafl_qemu::arch::arm::Regs;
        capture!("pc", Regs::Pc);
        capture!("sp", Regs::Sp);
        capture!("lr", Regs::Lr);
        capture!("r0", Regs::R0);
        capture!("r1", Regs::R1);
        capture!("r2", Regs::R2);
        capture!("r3", Regs::R3);
    }
    #[cfg(any(feature = "mips", feature = "mipsbe"))]
    {
        use libafl_qemu::arch::mips::Regs;
        capture!("pc", Regs::Pc);
        capture!("sp", Regs::Sp);
        capture!("ra", Regs::Ra);
        capture!("v0", Regs::V0);
        capture!("a0", Regs::A0);
        capture!("a1", Regs::A1);
        capture!("a2", Regs::A2);
        capture!("a3", Regs::A3);
    }
    #[cfg(feature = "x86_64")]
    {
        use libafl_qemu::arch::x86_64::Regs;
        capture!("pc", Regs::Rip);
        capture!("sp", Regs::Rsp);
        capture!("bp", Regs::Rbp);
        capture!("ret", Regs::Rax);
        capture!("arg0", Regs::Rdi);
        capture!("arg1", Regs::Rsi);
        capture!("arg2", Regs::Rdx);
        capture!("arg3", Regs::Rcx);
        capture!("arg4", Regs::R8);
        capture!("arg5", Regs::R9);
    }
    let pc = values
        .iter()
        .find(|item| item.name == "pc")
        .map(|item| item.value);
    let mut memory = Vec::new();
    if let Some(stack_pointer) = values
        .iter()
        .find(|item| item.name == "sp")
        .map(|item| item.value)
    {
        // A small stack window is useful for ABI/argument attribution while
        // remaining bounded. Unreadable guest pages are omitted rather than
        // turned into guessed bytes.
        let address = stack_pointer.saturating_sub(16);
        let mut bytes = vec![0_u8; 64];
        let error = qemu
            .read_mem(address as GuestAddr, &mut bytes)
            .err()
            .map(|error| format!("{error:?}"));
        if error.is_some() {
            bytes.clear();
        }
        memory.push(MemorySnapshot {
            address,
            requested_bytes: 64,
            source_register: "sp",
            bytes,
            error,
        });
    }
    (pc, values, memory)
}

/// Flush the current checkpoint without exposing the module tuple type.
pub fn flush_runtime_trace() {
    let ptr = GLOBAL_TRACE_MODULE_PTR.load(Ordering::Acquire);
    if ptr.is_null() {
        return;
    }
    unsafe {
        if let Err(error) = (*ptr).flush() {
            log::warn!("failed to flush runtime trace: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_snapshot_is_stable_and_atomic() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("trace.json");
        let mut trace = RuntimeTraceModule::new(path.clone());
        trace.max_unique_blocks = 2;
        trace.max_tail_entries = 2;
        trace.observe_block(0x20);
        trace.observe_block(0x10);
        trace.observe_block(0x10);
        trace.observe_block(0x30);
        trace.push_event("iib_hook", "unit-a@0x10".into());
        trace.flush().unwrap();

        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let heartbeat: serde_json::Value = serde_json::from_slice(
            &std::fs::read(temp.path().join("trace.heartbeat.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(value["total_block_executions"], 4);
        assert_eq!(value["schema_version"], 6);
        assert_eq!(value["main_load_address"], 0);
        assert_eq!(value["observed_unique_blocks"], 2);
        assert_eq!(value["dropped_unique_blocks"], 1);
        assert_eq!(value["blocks"][0]["pc"], 0x10);
        assert_eq!(value["events"][0]["kind"], "iib_hook");
        assert_eq!(value["events"][0]["repeat_count"], 1);
        assert_eq!(heartbeat["total_block_executions"], 4);
        assert_eq!(heartbeat["last_pc"], 0x30);
    }

    #[test]
    fn focused_tail_is_not_evicted_by_unrelated_blocks() {
        let mut trace = RuntimeTraceModule::disabled();
        trace.max_tail_entries = 2;
        trace.max_focus_tail_entries = 3;
        trace.focus_images = vec!["service".into()];
        trace.focus_ranges = vec![(0x1000, 0x2000)];
        trace.observe_block(0x1100);
        trace.observe_block(0x9000);
        trace.observe_block(0x9004);
        assert_eq!(trace.tail.front().unwrap().pc, 0x9000);
        assert_eq!(trace.focus_tail.front().unwrap().pc, 0x1100);
    }

    #[test]
    fn consecutive_identical_events_are_run_length_encoded() {
        let mut trace = RuntimeTraceModule::disabled();
        trace.push_event_with_state("iib_hook", "same".into(), Some(1), Vec::new(), Vec::new());
        trace.push_event_with_state("iib_hook", "same".into(), Some(1), Vec::new(), Vec::new());
        assert_eq!(trace.events.len(), 1);
        let event = trace.events.front().unwrap();
        assert_eq!(event.sequence, 1);
        assert_eq!(event.last_sequence, 2);
        assert_eq!(event.repeat_count, 2);
    }

    #[test]
    fn interesting_syscalls_are_named_for_the_selected_guest_architecture() {
        #[cfg(feature = "arm")]
        assert_eq!(interesting_syscall_name(282), Some("bind"));
        #[cfg(any(feature = "mips", feature = "mipsbe"))]
        assert_eq!(interesting_syscall_name(4169), Some("bind"));
        #[cfg(feature = "x86_64")]
        assert_eq!(interesting_syscall_name(49), Some("bind"));
        assert_eq!(interesting_syscall_name(-1), None);
    }
}
