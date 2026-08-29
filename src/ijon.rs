//! This file contains the generic IJON-style state feedback implementation
//!
//! SPDX-License-Identifier: MIT
//! Copyright (c) 2026 h0mbre

use std::collections::{hash_map::Entry, HashMap, HashSet};
use std::fmt;

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

/// Per-pair directional state and words needed for every possible distance
/// bucket on a usize target. Pair-slot collisions may suppress novelty, but
/// cannot create an unbounded stream of findings.
const DISTANCE_DIRECTIONS: usize = 2;
const DISTANCE_BUCKET_WORDS: usize = 2;
const DISTANCE_UNSEEN: u8 = u8::MAX;

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
const FOUND_ORDER_FLIP: u8 = 1 << 7;

/// All generic state needed to evaluate IJON feedback for one fuzzer
pub struct Ijon {
    sets: HashSet<(usize, u64, u64)>,
    maximums: HashMap<(usize, u64), u64>,
    count_maximums: HashMap<(usize, u64), u64>,
    states: HashSet<(usize, u64, u64)>,
    events: HashSet<(usize, u64, Option<u64>, u64)>,
    run_counts: HashMap<(usize, u64), u64>,
    run_events: HashMap<(usize, u64), u64>,
    run_states: HashMap<(usize, u64), u64>,
    temporal_events: Vec<TemporalEvent>,
    temporal_direction_history: Vec<u8>,
    temporal_active: bool,
    distance_history: Vec<[u64; DISTANCE_BUCKET_WORDS]>,
    nearest_history: Vec<u8>,
    farthest_history: Vec<u8>,
    distance_pending: Vec<DistanceFeedback>,
    proximity_pending: Vec<FrontierFeedback>,
    separation_pending: Vec<FrontierFeedback>,
    pending: u8,
}

/// One newly observed distance bucket for a directed temporal pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DistanceFeedback {
    pub pair_slot: u16,
    pub direction: u8,
    pub bucket: u8,
    pub distance: usize,
}

/// One improvement to a directed temporal pair's nearest or farthest frontier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrontierFeedback {
    pub pair_slot: u16,
    pub direction: u8,
    pub previous_bucket: u8,
    pub bucket: u8,
    pub distance: usize,
}

/// IJON feedback classes discovered by one input.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IjonFeedback {
    pub set: bool,
    pub maximum: bool,
    pub increment: bool,
    pub state: bool,
    pub event: bool,
    pub temporal: bool,
    pub order_flip: bool,
    pub distance: Vec<DistanceFeedback>,
    pub proximity: Vec<FrontierFeedback>,
    pub separation: Vec<FrontierFeedback>,
}

impl fmt::Display for IjonFeedback {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut found = Vec::new();
        if self.set {
            found.push(String::from("SET"));
        }
        if self.maximum {
            found.push(String::from("MAX"));
        }
        if self.increment {
            found.push(String::from("INC"));
        }
        if self.state {
            found.push(String::from("STATE"));
        }
        if self.event {
            found.push(String::from("EVENT"));
        }
        if self.temporal {
            found.push(String::from("TEMPORAL"));
        }
        if self.order_flip {
            found.push(String::from("ORDER_FLIP"));
        }
        if !self.distance.is_empty() {
            found.push(format!("DISTANCE(discoveries={})", self.distance.len()));
        }
        if let Some(best) = self.proximity.iter().min_by_key(|feedback| feedback.bucket) {
            found.push(format!(
                "PROXIMITY(bucket={}, pair=0x{:04X}, direction={}, previous={}, distance={}, improvements={})",
                best.bucket,
                best.pair_slot,
                best.direction,
                best.previous_bucket,
                best.distance,
                self.proximity.len()
            ));
        }
        if let Some(best) = self
            .separation
            .iter()
            .max_by_key(|feedback| feedback.bucket)
        {
            found.push(format!(
                "SEPARATION(bucket={}, pair=0x{:04X}, direction={}, previous={}, distance={}, improvements={})",
                best.bucket,
                best.pair_slot,
                best.direction,
                best.previous_bucket,
                best.distance,
                self.separation.len()
            ));
        }
        formatter.write_str(&found.join(", "))
    }
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
            run_states: HashMap::new(),
            temporal_events: Vec::new(),
            temporal_direction_history: vec![0; TEMPORAL_MAP_SIZE],
            temporal_active: false,
            distance_history: vec![
                [0; DISTANCE_BUCKET_WORDS];
                TEMPORAL_MAP_SIZE * DISTANCE_DIRECTIONS
            ],
            nearest_history: vec![DISTANCE_UNSEEN; TEMPORAL_MAP_SIZE * DISTANCE_DIRECTIONS],
            farthest_history: vec![DISTANCE_UNSEEN; TEMPORAL_MAP_SIZE * DISTANCE_DIRECTIONS],
            distance_pending: Vec::new(),
            proximity_pending: Vec::new(),
            separation_pending: Vec::new(),
            pending: 0,
        }
    }

    /// Reset state that is local to one fuzzing iteration
    pub fn begin_run(&mut self) {
        self.run_counts.clear();
        self.run_events.clear();
        self.run_states.clear();
        self.temporal_events.clear();

        self.distance_pending.clear();
        self.proximity_pending.clear();
        self.separation_pending.clear();
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
        // STATE describes an execution's final value at a semantic site. Do
        // not reward every intermediate prefix: only a different terminal
        // state is a durable, black-or-white semantic distinction.
        for (&(rip, tag), &value) in &self.run_states {
            if self.states.insert((rip, tag, value)) {
                self.pending |= FOUND_STATE;
            }
        }

        if !self.temporal_active || self.temporal_events.is_empty() {
            return;
        }

        let mut previous_events: HashMap<u64, TemporalEvent> = HashMap::new();
        let mut run_distances: HashMap<usize, HashMap<u8, usize>> = HashMap::new();

        // Every event replaces the prior event for its object, including
        // events on the same vCPU.  Only a resulting edge which crosses vCPUs
        // earns novelty.  Same-vCPU events remain part of the object's
        // history without duplicating ordinary code coverage.
        for event in &self.temporal_events {
            let previous = previous_events.insert(event.object_id, *event);

            let Some(previous) = previous else {
                continue;
            };

            if previous.cpu_id == event.cpu_id {
                continue;
            }

            // The emulator supplies one monotonically increasing, machine-
            // wide instruction position. A backwards or equal position is
            // not a meaningful directed distance and is ignored explicitly.
            let Some(distance) = event
                .instruction_count
                .checked_sub(previous.instruction_count)
            else {
                continue;
            };
            if distance == 0 {
                continue;
            }

            // Canonicalize the site pair and keep direction as independent
            // state. This lets both A->B and B->A share one pair identity
            // without conflating their distance coverage or frontiers.
            let (low, high, direction) = if previous.site_id <= event.site_id {
                (previous.site_id, event.site_id, 0usize)
            } else {
                (event.site_id, previous.site_id, 1usize)
            };
            let pair_slot = mix(low, high) as usize & (TEMPORAL_MAP_SIZE - 1);
            let directed_index = pair_slot * DISTANCE_DIRECTIONS + direction;
            let bucket = proximity_bucket(distance);

            // Preserve every bucket observed in this execution. For repeated
            // observations in one bucket, retain the exact distance nearest
            // that bucket's useful frontier for diagnostics.
            run_distances
                .entry(directed_index)
                .or_default()
                .entry(bucket)
                .and_modify(|recorded| {
                    if bucket <= 63 {
                        *recorded = (*recorded).min(distance);
                    } else {
                        *recorded = (*recorded).max(distance);
                    }
                })
                .or_insert(distance);
        }

        for (directed_index, buckets) in run_distances {
            let pair_slot = directed_index / DISTANCE_DIRECTIONS;
            let direction = (directed_index % DISTANCE_DIRECTIONS) as u8;
            let direction_bit = 1u8 << direction;
            let was_seen = self.temporal_direction_history[pair_slot] & direction_bit != 0;

            if !was_seen {
                if self.temporal_direction_history[pair_slot] & !direction_bit != 0 {
                    self.pending |= FOUND_ORDER_FLIP;
                }
                self.temporal_direction_history[pair_slot] |= direction_bit;
                self.pending |= FOUND_TEMPORAL;
            }

            let run_nearest = *buckets.keys().min().expect("temporal bucket set is empty");
            let run_farthest = *buckets.keys().max().expect("temporal bucket set is empty");
            let previous_nearest = self.nearest_history[directed_index];
            let previous_farthest = self.farthest_history[directed_index];

            for (&bucket, &distance) in &buckets {
                let word = bucket as usize / 64;
                let bit = 1u64 << (bucket as usize % 64);
                if self.distance_history[directed_index][word] & bit == 0 {
                    self.distance_history[directed_index][word] |= bit;
                    self.distance_pending.push(DistanceFeedback {
                        pair_slot: pair_slot as u16,
                        direction,
                        bucket,
                        distance,
                    });
                }
            }

            // The first observation initializes both frontiers but is only
            // temporal/distance coverage. Optimization feedback begins once
            // an established direction actually moves a frontier.
            if was_seen {
                if run_nearest < previous_nearest {
                    self.proximity_pending.push(FrontierFeedback {
                        pair_slot: pair_slot as u16,
                        direction,
                        previous_bucket: previous_nearest,
                        bucket: run_nearest,
                        distance: buckets[&run_nearest],
                    });
                }
                if run_farthest > previous_farthest {
                    self.separation_pending.push(FrontierFeedback {
                        pair_slot: pair_slot as u16,
                        direction,
                        previous_bucket: previous_farthest,
                        bucket: run_farthest,
                        distance: buckets[&run_farthest],
                    });
                }
            }

            self.nearest_history[directed_index] = previous_nearest.min(run_nearest);
            self.farthest_history[directed_index] = if previous_farthest == DISTANCE_UNSEEN {
                run_farthest
            } else {
                previous_farthest.max(run_farthest)
            };
        }
    }

    /// Check whether the current input found any new IJON feedback
    pub fn has_new_feedback(&self) -> bool {
        self.pending != 0
            || !self.distance_pending.is_empty()
            || !self.proximity_pending.is_empty()
            || !self.separation_pending.is_empty()
    }

    /// Consume all IJON feedback found by the current input
    pub fn take_feedback(&mut self) -> Option<IjonFeedback> {
        if !self.has_new_feedback() {
            return None;
        }

        let feedback = IjonFeedback {
            set: self.pending & FOUND_SET != 0,
            maximum: self.pending & FOUND_MAX != 0,
            increment: self.pending & FOUND_INC != 0,
            state: self.pending & FOUND_STATE != 0,
            event: self.pending & FOUND_EVENT != 0,
            temporal: self.pending & FOUND_TEMPORAL != 0,
            order_flip: self.pending & FOUND_ORDER_FLIP != 0,
            distance: std::mem::take(&mut self.distance_pending),
            proximity: std::mem::take(&mut self.proximity_pending),
            separation: std::mem::take(&mut self.separation_pending),
        };

        self.pending = 0;
        Some(feedback)
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
                self.run_states.insert((rip, tag), value);
            }
            IJON_EVENT => {
                // EVENT represents a semantic transition, not an ever-growing
                // sequence prefix. Repeated identical events are noise; a
                // new adjacent transition is a discrete ordering difference.
                let previous = self.run_events.insert((rip, tag), value);
                if previous != Some(value) && self.events.insert((rip, tag, previous, value)) {
                    self.pending |= FOUND_EVENT;
                }
            }
            _ => mega_panic!("Received invalid IJON operation"),
        }
    }
}

/// Convert an instruction distance to an exact-near, logarithmic-far bucket.
///
/// Buckets zero through 63 represent exact distances one through 64. Bucket
/// 64 represents distances 65 through 127, bucket 65 represents 128 through
/// 255, and subsequent buckets continue at power-of-two widths. Smaller
/// bucket numbers are always closer and are safe to compare directly.
fn proximity_bucket(distance: usize) -> u8 {
    const EXACT_DISTANCE_LIMIT: usize = 64;

    if distance <= EXACT_DISTANCE_LIMIT {
        return (distance - 1) as u8;
    }

    let highest_bit = usize::BITS - distance.leading_zeros() - 1;
    (EXACT_DISTANCE_LIMIT as u32 + highest_bit - EXACT_DISTANCE_LIMIT.trailing_zeros()) as u8
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
