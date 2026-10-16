//! Hand-curated argument decoders for well-known APIs.
//!
//! Keeping a small corpus here means LLM-synthesized intervention code
//! can use strongly-typed accessors (`OpenArgs`, `IoctlArgs`, ...) rather
//! than reinvent argument parsing per target.

pub mod posix;
