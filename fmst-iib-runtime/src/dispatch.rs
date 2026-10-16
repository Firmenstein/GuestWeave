//! Maps resolved guest PC → ordered list of (flavor, entry_fn) to invoke.
//!
//! Multiple hooks at the same PC are allowed and run FIFO. Build.rs emits
//! a cargo warning for these (see IIB-MANIFEST-003).

use fmst_iib_api::context::IIBContextOps;
use fmst_iib_api::types::{GuestAddr, HookFlavor};
use std::collections::HashMap;

pub type HookFn = fn(&mut dyn IIBContextOps);

#[derive(Clone, Copy)]
pub struct DispatchEntry {
    pub flavor: HookFlavor,
    pub entry_fn: HookFn,
    pub id: &'static str,
    /// Runtime PC after an intercepted call instruction. Function-entry
    /// stubs retain None and return through the architecture's native ABI.
    pub callsite_resume_pc: Option<GuestAddr>,
}

pub struct DispatchTable {
    by_pc: HashMap<GuestAddr, Vec<DispatchEntry>>,
}

impl DispatchTable {
    pub fn new() -> Self {
        Self {
            by_pc: HashMap::new(),
        }
    }

    pub fn register(&mut self, pc: GuestAddr, entry: DispatchEntry) {
        self.by_pc.entry(pc).or_default().push(entry);
    }

    pub fn get(&self, pc: GuestAddr) -> Option<&[DispatchEntry]> {
        self.by_pc.get(&pc).map(|v| v.as_slice())
    }

    pub fn unique_pcs(&self) -> impl Iterator<Item = GuestAddr> + '_ {
        self.by_pc.keys().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noop(_: &mut dyn IIBContextOps) {}

    #[test]
    fn fifo_order_preserved() {
        let mut t = DispatchTable::new();
        t.register(
            0x1000,
            DispatchEntry {
                flavor: HookFlavor::Call,
                entry_fn: noop,
                id: "first",
                callsite_resume_pc: Some(0x1004),
            },
        );
        t.register(
            0x1000,
            DispatchEntry {
                flavor: HookFlavor::Enter,
                entry_fn: noop,
                id: "second",
                callsite_resume_pc: None,
            },
        );
        let entries = t.get(0x1000).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].id, "first");
        assert_eq!(entries[1].id, "second");
    }

    #[test]
    fn missing_pc_returns_none() {
        let t = DispatchTable::new();
        assert!(t.get(0x2000).is_none());
    }
}
