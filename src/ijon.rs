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
const IJON_TEMPORAL: usize = 5;

/// Number of slots in each temporal feedback map.
///
/// Keep this fixed for the first implementation.  Temporal feedback is only
/// active when a guest reports an IJON_TEMPORAL event, so ordinary harnesses
/// do not pay for clearing or evaluating these maps.
const TEMPORAL_MAP_SIZE: usize = 1 << 16;

/// Maximum number of complete events Bochs may pass in one callback.
///
/// This value must match TEMPORAL_EVENT_BUFFER_CAPACITY in the Bochs patch.
const TEMPORAL_EVENT_BUFFER_CAPACITY: usize = 1 << 10;

/// Bit values used to remember which IJON operations found new feedback
const FOUND_SET: u8 = 1 << IJON_SET;
const FOUND_MAX: u8 = 1 << IJON_MAX;
const FOUND_INC: u8 = 1 << IJON_INC;
const FOUND_STATE: u8 = 1 << IJON_STATE;
const FOUND_EVENT: u8 = 1 << IJON_EVENT;
const FOUND_TEMPORAL: u8 = 1 << IJON_TEMPORAL;

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
    temporal_events: Vec<TemporalEvent>,
    temporal_current_map: Vec<u8>,
    temporal_history_map: Vec<u8>,
    temporal_active: bool,
    pending: u8,
}

/// One semantic event reported by an instrumented guest during an iteration
///
/// Bochs constructs this record, so its layout is part of the C ABI between
/// the emulator and Lucid.  Object identifiers are meaningful only within the
/// current fuzzcase.  RIP and instruction count are retained as useful event
/// metadata, but they are intentionally not part of the persistent novelty
/// key.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TemporalEvent {
    pub rip: usize,
    pub site_id: u64,
    pub object_id: u64,
    pub cpu_id: usize,
    pub instruction_count: usize,
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
            temporal_events: Vec::new(),
            temporal_current_map: vec![0; TEMPORAL_MAP_SIZE],
            temporal_history_map: vec![0; TEMPORAL_MAP_SIZE],
            temporal_active: false,
            pending: 0,
        }
    }

    /// Reset state that is local to one fuzzing iteration
    pub fn begin_run(&mut self) {
        self.run_counts.clear();
        self.run_events.clear();
        self.run_state = 0;
        self.temporal_events.clear();

        // Do not add a map clear to harnesses which never request temporal
        // feedback.  Once a harness has emitted a temporal event, this map is
        // ordinary execution-local state and must be cleared for every run.
        if self.temporal_active {
            self.temporal_current_map.fill(0);
        }
        self.pending = 0;
    }

    /// Append one complete batch reported by Bochs.
    fn record_temporal_batch(&mut self, events: &[TemporalEvent]) {
        self.temporal_active = true;
        self.temporal_events.extend_from_slice(events);
    }

    /// Finish IJON feedback processing for the current fuzzing iteration.
    ///
    /// Keeping this as one generic lifecycle hook prevents the fuzzing loop
    /// from needing to know which IJON feedback types require finalization.
    /// New IJON feedback mechanisms can be finished here in the future.
    pub fn post_fuzz(&mut self) {
        if !self.temporal_active || self.temporal_events.is_empty() {
            return;
        }

        let mut previous_events: HashMap<u64, (u64, usize)> = HashMap::new();

        // Every event replaces the prior event for its object, including
        // events on the same vCPU.  Only a resulting edge which crosses vCPUs
        // earns novelty.  Same-vCPU events remain part of the object's
        // history without duplicating ordinary code coverage.
        for event in &self.temporal_events {
            let previous = previous_events.insert(event.object_id, (event.site_id, event.cpu_id));

            let Some((previous_site, previous_cpu)) = previous else {
                continue;
            };

            if previous_cpu == event.cpu_id {
                continue;
            }

            // Object IDs only separate simultaneous lifetimes inside this
            // fuzzcase.  Excluding the ID here lets an equivalent lifetime in
            // a later fuzzcase map to the same persistent temporal edge.
            let mut hash = mix(previous_site, previous_cpu as u64);
            hash = mix(hash, event.site_id);
            hash = mix(hash, event.cpu_id as u64);
            let index = hash as usize & (TEMPORAL_MAP_SIZE - 1);

            self.temporal_current_map[index] = 1;
            if self.temporal_history_map[index] == 0 {
                self.temporal_history_map[index] = 1;
                self.pending |= FOUND_TEMPORAL;
            }
        }
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
        if self.pending & FOUND_TEMPORAL != 0 {
            found.push("TEMPORAL");
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
    _cpu_id: usize,
    _instruction_count: usize,
) {
    // Ensure that Bochs passed back a valid execution context
    if !LucidContext::is_valid(contextp) {
        mega_panic!("Invalid context pointer passed to lucid_report_ijon");
    }

    // Temporal operation 5 uses the existing callback as a batch transport.
    // Bochs passes a pointer in `tag` and a record count in `value`; the other
    // event arguments are zero.  Operations 0 through 4 keep their original
    // scalar meaning.
    let context = unsafe { &mut *contextp };
    if operation == IJON_TEMPORAL {
        let event_count = value as usize;
        if tag == 0 || event_count == 0 || event_count > TEMPORAL_EVENT_BUFFER_CAPACITY {
            mega_panic!("Invalid temporal IJON event batch");
        }

        let event_pointer = tag as usize as *const TemporalEvent;
        let events = unsafe { std::slice::from_raw_parts(event_pointer, event_count) };
        context.ijon.record_temporal_batch(events);
        return;
    }

    // Update generic IJON feedback independently from normal edge coverage
    context.ijon.report(operation, rip, tag, value);

    // Include all semantic feedback in the trace identity used by Redqueen
    if matches!(context.cpu_mode, CpuMode::TraceHash) {
        let event = mix(mix(rip as u64, operation as u64), mix(tag, value));
        context.trace_hash = hash_trace(context.trace_hash, event);
        context.trace_hash = hash_trace(context.trace_hash, event >> 32);
    }
}
