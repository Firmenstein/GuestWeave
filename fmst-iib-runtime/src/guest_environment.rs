//! Host-environment handoff used while QEMU builds a re-exec'd guest image.
//!
//! QEMU's `-E` parser treats commas as a list separator.  A guest environment
//! value may contain commas (and need not be UTF-8), so re-exec uses the host
//! environment as a byte-preserving staging channel instead.  The guard keeps
//! this mutation limited to QEMU initialization and restores the harness
//! environment before guest execution resumes.

use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};

#[derive(Debug)]
pub struct HostEnvironmentGuard {
    original: Vec<(OsString, OsString)>,
}

impl Drop for HostEnvironmentGuard {
    fn drop(&mut self) {
        let current = std::env::vars_os().map(|(key, _)| key).collect::<Vec<_>>();
        for key in current {
            std::env::remove_var(key);
        }
        for (key, value) in &self.original {
            std::env::set_var(key, value);
        }
    }
}

fn split_environment_entry(value: &OsStr) -> Result<(OsString, OsString), String> {
    let bytes = value.as_bytes();
    let separator = bytes
        .iter()
        .position(|byte| *byte == b'=')
        .ok_or_else(|| "guest environment entry has no '='".to_owned())?;
    if separator == 0 {
        return Err("guest environment entry has an empty name".to_owned());
    }
    Ok((
        OsString::from_vec(bytes[..separator].to_vec()),
        OsString::from_vec(bytes[separator + 1..].to_vec()),
    ))
}

/// Stage a non-empty guest environment in the host environment for QEMU's
/// initial copy, returning the complete set of names that must be removed
/// from the guest view.  An empty `guest_env` preserves the historical startup
/// behavior, where the container environment is already the guest baseline.
pub fn prepare_guest_environment(
    guest_env: &[OsString],
    requested_unset: &[OsString],
) -> Result<(Option<HostEnvironmentGuard>, Vec<OsString>), String> {
    if guest_env.is_empty() {
        return Ok((None, requested_unset.to_vec()));
    }

    let mut parsed = Vec::with_capacity(guest_env.len());
    let mut names = HashSet::with_capacity(guest_env.len());
    for value in guest_env {
        let (name, content) = split_environment_entry(value)?;
        if !names.insert(name.clone()) {
            return Err(format!(
                "guest environment contains duplicate name {:?}",
                name.to_string_lossy()
            ));
        }
        parsed.push((name, content));
    }

    let original = std::env::vars_os().collect::<Vec<_>>();
    for (name, value) in &parsed {
        std::env::set_var(name, value);
    }

    let mut unset = Vec::new();
    let mut seen_unset = HashSet::new();
    for name in requested_unset.iter().chain(
        original
            .iter()
            .map(|(name, _)| name)
            .filter(|name| !names.contains(*name)),
    ) {
        if !names.contains(name) && seen_unset.insert(name.clone()) {
            unset.push(name.clone());
        }
    }

    Ok((Some(HostEnvironmentGuard { original }), unset))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_preserves_comma_and_non_utf8_value() {
        let entry = OsString::from_vec(b"FMST_BYTE=A,\xffB".to_vec());
        let (name, value) = split_environment_entry(&entry).unwrap();
        assert_eq!(name, OsString::from("FMST_BYTE"));
        assert_eq!(value.as_os_str().as_bytes(), b"A,\xffB");
    }

    #[test]
    fn invalid_and_duplicate_entries_are_rejected_before_mutation() {
        let invalid = vec![OsString::from("INVALID")];
        assert!(prepare_guest_environment(&invalid, &[]).is_err());
        let empty_name = vec![OsString::from("=value")];
        assert!(prepare_guest_environment(&empty_name, &[]).is_err());

        let duplicate = vec![OsString::from("A=1"), OsString::from("A=2")];
        assert!(prepare_guest_environment(&duplicate, &[]).is_err());
    }
}
