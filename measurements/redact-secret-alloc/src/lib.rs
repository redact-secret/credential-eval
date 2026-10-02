//! Allocation request counting (ADR 0002, kind 2).
//!
//! The process-wide allocator is `stats_alloc` over the system allocator: a
//! maintained third-party counting wrapper, so this package contains no
//! `unsafe`. Counters hold request counts and sizes only; they never see a
//! pointer or the bytes of an allocation.
//!
//! # Counting semantics
//!
//! Issue #1121's harness counted every `alloc`, `alloc_zeroed` and `realloc`
//! request, and no deallocation. [`counted`] reports the same three request
//! kinds: `requests = alloc_requests + realloc_requests`. `stats_alloc`
//! records the byte size of an `alloc` request and, for a `realloc`, only the
//! size *difference* (growth adds to `bytes_allocated`, the signed net goes to
//! `bytes_reallocated`) rather than the new size, so the byte columns are
//! `allocated_bytes` (fresh requests plus realloc growth) and
//! `realloc_net_bytes`, not the harness's single cumulative total. The request counts, which the cards use as their
//! metric, are identical in meaning.
//!
//! The counters are process-wide: a measurement is only meaningful while no
//! other thread allocates. [`counted`] is for single-threaded harnesses and
//! `harness = false` tests.

#![forbid(unsafe_code)]

pub mod cores;
pub mod report;

use std::alloc::System;

use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};

#[global_allocator]
static ALLOCATOR: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

/// Allocator activity during one call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Activity {
    /// `alloc` and `alloc_zeroed` requests.
    pub alloc_requests: u64,
    /// `realloc` requests.
    pub realloc_requests: u64,
    /// Bytes requested by `alloc` and `alloc_zeroed`, plus the growth of every
    /// growing `realloc`.
    pub allocated_bytes: u64,
    /// Net bytes requested by `realloc`.
    pub realloc_net_bytes: i64,
}

/// Run `f` and report its allocator activity. Anything `f` returns is
/// returned after the region closes, so building a digest of the result
/// afterwards is not counted.
pub fn counted<T>(f: impl FnOnce() -> T) -> (T, Activity) {
    let region = Region::new(&INSTRUMENTED_SYSTEM);
    let value = f();
    let change = region.change();
    (
        value,
        Activity {
            alloc_requests: change.allocations as u64,
            realloc_requests: change.reallocations as u64,
            allocated_bytes: change.bytes_allocated as u64,
            realloc_net_bytes: change.bytes_reallocated as i64,
        },
    )
}
