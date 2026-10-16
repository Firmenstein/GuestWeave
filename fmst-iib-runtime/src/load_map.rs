//! Build a `binary_basename → load_base` map from a list of guest
//! memory-map entries.
//!
//! The runtime obtains the entries via `Qemu::mappings()` after the
//! one-shot entry hook fires (ld.so has completed). This module decouples
//! parsing from the libafl_qemu-specific source so it's unit-testable.

use fmst_iib_api::types::GuestAddr;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

/// Single map entry: a contiguous VM range backed by a named file.
#[derive(Debug, Clone)]
pub struct MapEntry {
    pub start: GuestAddr,
    pub end: GuestAddr,
    pub path: String,
    pub is_executable: bool,
}

/// A loaded basename cannot select one unique image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadMapError {
    /// A basename is not a stable image identity when two different guest
    /// paths with that basename are mapped at the same time.  Choosing one
    /// address would make hook resolution depend on map ordering.
    AmbiguousBasename {
        basename: String,
        paths: Vec<String>,
    },
}

impl std::fmt::Display for LoadMapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AmbiguousBasename { basename, paths } => write!(
                f,
                "guest image basename {basename:?} is mapped from multiple paths: {}",
                paths.join(", ")
            ),
        }
    }
}

/// Ambiguity belongs to a name, not the entire process: an unrelated mapped
/// file must not prevent resolving an unambiguous hook in another image.
pub type LoadMap = HashMap<String, Result<GuestAddr, LoadMapError>>;

/// Result of aggregating a sequence of `MapEntry` into per-binary load bases.
///
/// For each basename, keep the lowest file-backed mapping. The first PT_LOAD
/// segment is often read-only, so considering executable mappings alone would
/// shift PIE/shared-library bases by the text-segment offset.
pub fn build_load_map(entries: &[MapEntry]) -> LoadMap {
    let mut paths_by_basename: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut out: HashMap<String, GuestAddr> = HashMap::new();
    for e in entries {
        let basename = Path::new(&e.path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        if basename.is_empty() {
            continue;
        }
        paths_by_basename
            .entry(basename.clone())
            .or_default()
            .insert(e.path.clone());
        out.entry(basename)
            .and_modify(|v| {
                if e.start < *v {
                    *v = e.start;
                }
            })
            .or_insert(e.start);
    }
    let mut out: LoadMap = out
        .into_iter()
        .map(|(name, base)| (name, Ok(base)))
        .collect();
    for (basename, paths) in paths_by_basename {
        if paths.len() > 1 {
            let mut paths: Vec<_> = paths.into_iter().collect();
            paths.sort();
            out.insert(
                basename.clone(),
                Err(LoadMapError::AmbiguousBasename { basename, paths }),
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basename_extracted_from_path() {
        let entries = vec![
            MapEntry {
                start: 0x10000,
                end: 0x20000,
                path: "/usr/sbin/httpd".into(),
                is_executable: true,
            },
            MapEntry {
                start: 0x30000,
                end: 0x40000,
                path: "/lib/libc.so.6".into(),
                is_executable: true,
            },
        ];
        let m = build_load_map(&entries);
        assert_eq!(m.get("httpd"), Some(&Ok(0x10000)));
        assert_eq!(m.get("libc.so.6"), Some(&Ok(0x30000)));
    }

    #[test]
    fn read_only_first_load_segment_defines_pie_base() {
        let entries = vec![
            MapEntry {
                start: 0x10000,
                end: 0x20000,
                path: "/a/libnet.so".into(),
                is_executable: false,
            },
            MapEntry {
                start: 0x20000,
                end: 0x30000,
                path: "/a/libnet.so".into(),
                is_executable: true,
            },
        ];
        let m = build_load_map(&entries);
        assert_eq!(m.get("libnet.so"), Some(&Ok(0x10000)));
    }

    #[test]
    fn multiple_segments_pick_lowest() {
        let entries = vec![
            MapEntry {
                start: 0x30000,
                end: 0x40000,
                path: "/a/libc.so".into(),
                is_executable: true,
            },
            MapEntry {
                start: 0x20000,
                end: 0x30000,
                path: "/a/libc.so".into(),
                is_executable: true,
            },
            MapEntry {
                start: 0x40000,
                end: 0x50000,
                path: "/a/libc.so".into(),
                is_executable: true,
            },
        ];
        let m = build_load_map(&entries);
        assert_eq!(m.get("libc.so"), Some(&Ok(0x20000)));
    }

    #[test]
    fn anonymous_or_empty_path_skipped() {
        let entries = vec![MapEntry {
            start: 0x10000,
            end: 0x20000,
            path: "".into(),
            is_executable: true,
        }];
        let m = build_load_map(&entries);
        assert!(m.is_empty());
    }

    #[test]
    fn duplicate_basename_from_distinct_paths_is_an_explicit_error() {
        let entries = vec![
            MapEntry {
                start: 0x10000,
                end: 0x20000,
                path: "/lib/codec.so".into(),
                is_executable: true,
            },
            MapEntry {
                start: 0x30000,
                end: 0x40000,
                path: "/usr/lib/codec.so".into(),
                is_executable: true,
            },
        ];
        assert_eq!(
            build_load_map(&entries)["codec.so"],
            Err(LoadMapError::AmbiguousBasename {
                basename: "codec.so".into(),
                paths: vec!["/lib/codec.so".into(), "/usr/lib/codec.so".into()],
            })
        );
        let mut reversed = entries.clone();
        reversed.reverse();
        reversed.push(MapEntry {
            start: 0x50000,
            end: 0x60000,
            path: "/bin/service".into(),
            is_executable: true,
        });
        let map = build_load_map(&reversed);
        assert_eq!(map["codec.so"], build_load_map(&entries)["codec.so"]);
        assert_eq!(map["service"], Ok(0x50000));
    }

    #[test]
    fn repeated_segments_from_one_path_are_not_ambiguous() {
        let entries = vec![
            MapEntry {
                start: 0x30000,
                end: 0x40000,
                path: "/lib/codec.so".into(),
                is_executable: true,
            },
            MapEntry {
                start: 0x10000,
                end: 0x20000,
                path: "/lib/codec.so".into(),
                is_executable: false,
            },
        ];
        let map = build_load_map(&entries);
        assert_eq!(map.get("codec.so"), Some(&Ok(0x10000)));
    }
}
