//! This file contains the generic IJON-style state feedback implementation
//!
//! SPDX-License-Identifier: MIT
//! Copyright (c) 2026 h0mbre

use std::collections::{hash_map::Entry, HashMap, HashSet};

use crate::context::{CpuMode, LucidContext};
use crate::mega_panic;

/// The IJON operation values passed by the instrumented guest
const IJON_SET: usize = 0;
const IJON_MAX: usize = 1;
const IJON_INC: usize = 2;
const IJON_STATE: usize = 3;
const IJON_EVENT: usize = 4;

/// Bit values used to remember which IJON operations found new feedback
const FOUND_SET: u8 = 1 << IJON_SET;
const FOUND_MAX: u8 = 1 << IJON_MAX;
const FOUND_INC: u8 = 1 << IJON_INC;
const FOUND_STATE: u8 = 1 << IJON_STATE;
const FOUND_EVENT: u8 = 1 << IJON_EVENT;

/// All generic state needed to evaluate IJON feedback for one fuzzer
pub struct Ijon {
    sets: HashSet<(usize, u64, u64)>,
    maximums: HashMap<(usize, u64), u64>,
    count_maximums: HashMap<(usize, u64), u64>,
    states: HashSet<(usize, u64, u64)>,
    events: HashSet<(usize, u64, u64)>,
    run_counts: HashMap<(usize, u64), u64>,
    run_events: HashMap<(usize, u64), u64>,
    run_state: u64,
    pending: u8,
}

impl Ijon {
    /// Create an empty IJON feedback state
    pub fn new() -> Self {
        Self {
            sets: HashSet::new(),
            maximums: HashMap::new(),
            count_maximums: HashMap::new(),
            states: HashSet::new(),
            events: HashSet::new(),
            run_counts: HashMap::new(),
            run_events: HashMap::new(),
            run_state: 0,
            pending: 0,
        }
    }

    /// Reset state that is local to one fuzzing iteration
    pub fn begin_run(&mut self) {
        self.run_counts.clear();
        self.run_events.clear();
        self.run_state = 0;
        self.pending = 0;
    }

    /// Check whether the current input found any new IJON feedback
    pub fn has_new_feedback(&self) -> bool {
        self.pending != 0
    }

    /// Consume and describe all IJON feedback found by the current input
    pub fn take_feedback(&mut self) -> Option<String> {
        if self.pending == 0 {
            return None;
        }

        let mut found = Vec::new();
        if self.pending & FOUND_SET != 0 {
            found.push("SET");
        }
        if self.pending & FOUND_MAX != 0 {
            found.push("MAX");
        }
        if self.pending & FOUND_INC != 0 {
            found.push("INC");
        }
        if self.pending & FOUND_STATE != 0 {
            found.push("STATE");
        }
        if self.pending & FOUND_EVENT != 0 {
            found.push("EVENT");
        }

        self.pending = 0;
        Some(found.join(", "))
    }

    /// Process one IJON operation reported by the guest
    fn report(&mut self, operation: usize, rip: usize, tag: u64, value: u64) {
        match operation {
            IJON_SET => {
                if self.sets.insert((rip, tag, value)) {
                    self.pending |= FOUND_SET;
                }
            }
            IJON_MAX => match self.maximums.entry((rip, tag)) {
                Entry::Vacant(entry) => {
                    entry.insert(value);
                    self.pending |= FOUND_MAX;
                }
                Entry::Occupied(mut entry) if value > *entry.get() => {
                    entry.insert(value);
                    self.pending |= FOUND_MAX;
                }
                Entry::Occupied(_) => {}
            },
            IJON_INC => {
                let count = self.run_counts.entry((rip, tag)).or_insert(0);
                *count = count.saturating_add(1);

                let maximum = self.count_maximums.entry((rip, tag)).or_insert(0);
                if *count > *maximum {
                    *maximum = *count;
                    self.pending |= FOUND_INC;
                }
            }
            IJON_STATE => {
                self.run_state = mix(self.run_state, mix(tag, value));
                if self.states.insert((rip, tag, self.run_state)) {
                    self.pending |= FOUND_STATE;
                }
            }
            IJON_EVENT => {
                let sequence = self.run_events.entry((rip, tag)).or_insert(0);
                *sequence = mix(*sequence, value);
                if self.events.insert((rip, tag, *sequence)) {
                    self.pending |= FOUND_EVENT;
                }
            }
            _ => mega_panic!("Received invalid IJON operation"),
        }
    }
}

/// Mix two 64-bit values so all input bits influence state and event feedback
#[inline]
fn mix(left: u64, right: u64) -> u64 {
    let mut hash = left ^ right.wrapping_add(0x9e3779b97f4a7c15);
    hash ^= hash >> 30;
    hash = hash.wrapping_mul(0xbf58476d1ce4e5b9);
    hash ^= hash >> 27;
    hash = hash.wrapping_mul(0x94d049bb133111eb);
    hash ^ (hash >> 31)
}

/// Add one value to the same trace hash that Bochs uses for Redqueen
#[inline]
fn hash_trace(hash: usize, value: u64) -> usize {
    let hash = if hash == 0 { 5381 } else { hash };
    hash.wrapping_mul(33).wrapping_add(value as u32 as usize)
}

/// Callback used by Bochs to report an IJON operation to Lucid
#[no_mangle]
pub extern "C" fn lucid_report_ijon(
    contextp: *mut LucidContext,
    operation: usize,
    tag: u64,
    value: u64,
    rip: usize,
) {
    // Ensure that Bochs passed back a valid execution context
    if !LucidContext::is_valid(contextp) {
        mega_panic!("Invalid context pointer passed to lucid_report_ijon");
    }

    // Update generic IJON feedback independently from normal edge coverage
    let context = unsafe { &mut *contextp };
    context.ijon.report(operation, rip, tag, value);

    // Include all semantic feedback in the trace identity used by Redqueen
    if matches!(context.cpu_mode, CpuMode::TraceHash) {
        let event = mix(mix(rip as u64, operation as u64), mix(tag, value));
        context.trace_hash = hash_trace(context.trace_hash, event);
        context.trace_hash = hash_trace(context.trace_hash, event >> 32);
    }
}
