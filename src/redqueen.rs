//! This file contains all of the logic necessary to perform Redqueen operations
//! during fuzzing
//!
//! SPDX-License-Identifier: MIT
//! Copyright (c) 2025 h0mbre

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::ops::Range;

use crate::context::{
    fuzz_one, handle_crash, handle_new_coverage, handle_timeout, CpuMode, FuzzingResult,
    FuzzingStage, LucidContext,
};
use crate::err::LucidErr;
use crate::mega_panic;

/// This is the number of unique Redqueen inputs we keep historical record of
/// at once. This represents the last 10k unique inputs we've tried. This helps
/// us make sure we deduplicate inputs and don't waste cycles on frequently
/// created inputs
const HASH_SET_SIZE: usize = 500_000;

/// How large operands must be for us to work on them/encode them in bytes
const OP_FILTER_SIZE: usize = 4;

/// How many inputs we place in the test queue for Redqueen
const TEST_QUEUE_MAX: usize = 500;

/// Representation of an operand that was reported by Bochs
#[derive(Eq, Hash, PartialEq, Clone, Copy, Debug)]
enum Operand {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
}

/// Various encoding schemes that are used to encode operand values
#[derive(Clone, Copy, Debug)]
enum Encoding {
    Raw8(u8),
    Raw16(u16),
    Raw32(u32),
    Raw64(u64),
    ZeroExtend16(u16),
    ZeroExtend32(u32),
    ZeroExtend64(u64),
    SignExtend8(i8),
    SignExtend16(i16),
    SignExtend32(i32),
    SignExtend64(i64),
    ZeroReduce8(u8),
    ZeroReduce16(u16),
    ZeroReduce32(u32),
    SignReduce8(i8),
    SignReduce16(i16),
    SignReduce32(i32),
    BeZeroExtend16(u16),
    BeZeroExtend32(u32),
    BeZeroExtend64(u64),
    BeSignExtend8(i8),
    BeSignExtend16(i16),
    BeSignExtend32(i32),
    BeSignExtend64(i64),
    BeZeroReduce8(u8),
    BeZeroReduce16(u16),
    BeZeroReduce32(u32),
    BeSignReduce8(i8),
    BeSignReduce16(i16),
    BeSignReduce32(i32),
}

impl Encoding {
    /// Transforms an encoded operand value to a vector of bytes
    pub fn to_bytes(self) -> Vec<u8> {
        match self {
            // Little endian
            Encoding::Raw8(val) => val.to_le_bytes().to_vec(),
            Encoding::Raw16(val) => val.to_le_bytes().to_vec(),
            Encoding::Raw32(val) => val.to_le_bytes().to_vec(),
            Encoding::Raw64(val) => val.to_le_bytes().to_vec(),
            Encoding::ZeroExtend16(val) => val.to_le_bytes().to_vec(),
            Encoding::ZeroExtend32(val) => val.to_le_bytes().to_vec(),
            Encoding::ZeroExtend64(val) => val.to_le_bytes().to_vec(),
            Encoding::SignExtend8(val) => val.to_le_bytes().to_vec(),
            Encoding::SignExtend16(val) => val.to_le_bytes().to_vec(),
            Encoding::SignExtend32(val) => val.to_le_bytes().to_vec(),
            Encoding::SignExtend64(val) => val.to_le_bytes().to_vec(),
            Encoding::ZeroReduce8(val) => val.to_le_bytes().to_vec(),
            Encoding::ZeroReduce16(val) => val.to_le_bytes().to_vec(),
            Encoding::ZeroReduce32(val) => val.to_le_bytes().to_vec(),
            Encoding::SignReduce8(val) => val.to_le_bytes().to_vec(),
            Encoding::SignReduce16(val) => val.to_le_bytes().to_vec(),
            Encoding::SignReduce32(val) => val.to_le_bytes().to_vec(),

            // Big endian
            Encoding::BeZeroExtend16(val) => val.to_be_bytes().to_vec(),
            Encoding::BeZeroExtend32(val) => val.to_be_bytes().to_vec(),
            Encoding::BeZeroExtend64(val) => val.to_be_bytes().to_vec(),
            Encoding::BeSignExtend8(val) => val.to_be_bytes().to_vec(),
            Encoding::BeSignExtend16(val) => val.to_be_bytes().to_vec(),
            Encoding::BeSignExtend32(val) => val.to_be_bytes().to_vec(),
            Encoding::BeSignExtend64(val) => val.to_be_bytes().to_vec(),
            Encoding::BeZeroReduce8(val) => val.to_be_bytes().to_vec(),
            Encoding::BeZeroReduce16(val) => val.to_be_bytes().to_vec(),
            Encoding::BeZeroReduce32(val) => val.to_be_bytes().to_vec(),
            Encoding::BeSignReduce8(val) => val.to_be_bytes().to_vec(),
            Encoding::BeSignReduce16(val) => val.to_be_bytes().to_vec(),
            Encoding::BeSignReduce32(val) => val.to_be_bytes().to_vec(),
        }
    }
}

/// Type aliases for readability
type BytePair = (Vec<u8>, Vec<u8>);
type BytePairList = Vec<BytePair>;

/// Redqueen manages all of the mutable state required to track operands
/// reported by Bochs, create inputs based on the operand values, and
/// deduplicates generated inputs
#[derive(Clone)]
pub struct Redqueen {
    // A hashmap that contains the RIP for the compare instruction along with
    // a collection of operand tuples seen at that RIP for a single pass
    // Key: RIP, Value: [(op1, op2), (op1, op2), ...]
    cmp_operand_map: HashMap<usize, BytePairList>,

    // A collection of inputs that Redqueen needs to process
    pub process_queue: Vec<Vec<u8>>,

    // A collection of inputs that Redqueen crafted that we need to test
    pub test_queue: VecDeque<Vec<u8>>,

    // The last n inputs we added to queue (dedupe heuristic)
    hash_set: HashSet<u64>,
    hash_queue: VecDeque<u64>,

    // Collection of RIPs we've seen
    rip_set: HashSet<usize>,
}

impl Redqueen {
    /// Creates as new instance of a Redqueen struct
    pub fn new() -> Self {
        Redqueen {
            cmp_operand_map: HashMap::new(),
            process_queue: Vec::new(),
            test_queue: VecDeque::new(),
            hash_set: HashSet::with_capacity(HASH_SET_SIZE),
            hash_queue: VecDeque::with_capacity(HASH_SET_SIZE),
            rip_set: HashSet::new(),
        }
    }

    /// Converts an operand value to a vector of bytes, operands are cast to a
    /// usize but also callers pass in the operand size to get an appopriately
    /// sized vector returned
    fn usize_to_vec(value: usize, size: usize) -> Vec<u8> {
        let num_bytes = size / 8;
        let mut vec = Vec::new();
        for i in 0..num_bytes {
            vec.push(((value >> (i * 8)) & 0xFF) as u8);
        }

        // Return byte vec repr of value
        vec
    }

    /// Updates Redqueen's operand hashmap with a new entry where RIP is the
    /// entry key of where the compare operation took place, op1 and op2 are
    /// the operands in the comparison, and size is the size of the operands
    /// in bytes
    pub fn update_operands(&mut self, rip: usize, op1: usize, op2: usize, size: usize) {
        // Skip small operands
        if size < (OP_FILTER_SIZE * 8) {
            return;
        }

        // Skip zeros
        if op1 == 0 || op2 == 0 {
            return;
        }

        // If we've seen this RIP before, skip it
        if self.rip_set.contains(&rip) {
            return;
        }

        // Mark RIP as seen
        self.rip_set.insert(rip);

        // Create byte reprs for the operands
        let op1 = Self::usize_to_vec(op1, size);
        let op2 = Self::usize_to_vec(op2, size);

        // Update the map with the operands, avoiding duplicates
        let operands = self.cmp_operand_map.entry(rip).or_default();
        if !operands.contains(&(op1.clone(), op2.clone())) {
            operands.push((op1, op2));
        }
    }
}

/// Called by Bochs when executing with Redqueen CpuMode, this function will
/// update the Redqueen operand map with information about a compare operation
pub extern "C" fn lucid_report_cmps(
    contextp: *mut LucidContext,
    op1: usize,
    op2: usize,
    op_size: usize,
    rip: usize,
) {
    // We have to make sure this bad boy isn't NULL
    if !LucidContext::is_valid(contextp) {
        mega_panic!("Invalid context\n");
    }

    // Get the context
    let context = LucidContext::from_ptr_mut(contextp);

    // Update the Redqueen compare operand map
    context.redqueen.update_operands(rip, op1, op2, op_size);
}

/// Changes the Bochs CpuMode to TraceHash which will force Bochs to hash
/// all of the PCs that are executed for the current input. This function is
/// used to determine if changes to the input affect the execution paths
fn input_trace_hash(context: &mut LucidContext) -> Result<(usize, FuzzingResult), LucidErr> {
    // Change Bochs' CPU mode to hash trace mode
    let backup_cpu = context.cpu_mode;
    context.cpu_mode = CpuMode::TraceHash;

    // Re-execute the current input
    let fuzzing_result = fuzz_one(context)?;

    // Retrieve the hash
    let hash = context.trace_hash;

    // Clear the hash
    context.trace_hash = 0;

    // Reset Bochs' CPU mode
    context.cpu_mode = backup_cpu;

    Ok((hash, fuzzing_result))
}

/// Colorization seeks to increase the amount of randomness in an input so that
/// we can better identify where operand values in compare operations might
/// be sourced from in the input. If an input contained almost all zeros for
/// example, it would be difficult to pinpoint where exactly a 0u64 operand
/// value was sourced from in the input. This algorithm randomizes bytes in
/// the input, checks to see if the execution path was affected, if it was
/// affected, it then reduces the amount of randomness and tries again until
/// we've introduced as much randomness as possible without affecting the
/// execution path
fn colorize_input(
    context: &mut LucidContext,
    orig_hash: usize,
    idx: usize,
) -> Result<(), LucidErr> {
    // Get the field we want to colorize
    let mut colorized_field = context.mutator.get_redqueen_field(idx)?;

    // Initialize ranges with the length of the field
    let mut ranges: VecDeque<Range<usize>> = VecDeque::new();
    ranges.push_back(0..colorized_field.len());

    // Get the old edge count in case we increase code coverage with colorization
    let mut old_edge_count;

    // Set stage to Colorization
    let backup_stage = context.fuzzing_stage;
    context.fuzzing_stage = FuzzingStage::Colorization;

    // In a loop, try to add as much random bytes to the input as possible.
    // If we get the same execution hash we keep that input around and try to
    // randomize more, so everytime a range doesn't work for us, split it in
    // half and try again.
    // Example for a 64-byte input:
    // 1. Randomizing all 64 bytes changes execution hash
    // 2. We try 0..32 and 32..64
    // 3. 0..32 works for us, save this input and keep iterating on it
    // 4. 32..64 does not work, changes hash, we add 32-48 and 48-64 to ranges
    // 5. 32..48 fails, add 32-40 and 40-48 to ranges
    // 6. 48..64 works, save this input and keep iterating on it
    // 7. Continue until there are no more ranges to try
    while let Some(range) = ranges.pop_front() {
        // Update old edge count
        old_edge_count = context.coverage.get_edge_count();

        // Take backup of field before we alter it
        let backup_field = colorized_field.clone();

        // Replace bytes in the range with random bytes
        for byte in &mut colorized_field[range.clone()] {
            *byte = context.mutator.rand() as u8;
        }

        // Set new field
        context
            .mutator
            .set_redqueen_field(idx, colorized_field.clone())?;

        // Re-assemble input with new field value
        context.mutator.reassemble_redqueen_fields()?;

        // Execute the fuzzcase
        let (new_hash, fuzzing_result) = input_trace_hash(context)?;

        // FuzzingResult must be None if hash is the same
        if new_hash == orig_hash && fuzzing_result != FuzzingResult::None {
            return Err(LucidErr::from(
                "Redqueen colorization hash was same, but FuzzingResult != None",
            ));
        }

        // Hashes matched, keep coloring the field
        if new_hash == orig_hash {
            continue;
        }
        // Hashes didn't match
        else {
            // First try to handle any significant fuzzing results
            match fuzzing_result {
                FuzzingResult::NewCoverage => {
                    handle_new_coverage(context, old_edge_count);
                }
                FuzzingResult::Crash => {
                    handle_crash(context);
                }
                FuzzingResult::Timeout => {
                    handle_timeout(context);
                }
                FuzzingResult::None => (),
            }

            // Restore the original field value since execution changed
            colorized_field = backup_field;

            // Make sure the mutator input reverts back to a known good
            context
                .mutator
                .set_redqueen_field(idx, colorized_field.clone())?;
            context.mutator.reassemble_redqueen_fields()?;

            // Handle one-byte range
            if range.len() <= 1 {
                continue;
            }

            // Split the range in half
            let middle = range.start + (range.end - range.start) / 2;

            // Add new ranges to the collection to test
            if range.start < middle {
                ranges.push_back(range.start..middle);
            }

            if middle < range.end {
                ranges.push_back(middle..range.end);
            }
        }
    }

    // Reset stage
    context.fuzzing_stage = backup_stage;

    // Success
    Ok(())
}

/// Changes the CpuMode for the LucidContext to Cmplog which will force Bochs
/// to report all compare operations it simulates as it's simulating them and
/// update the Redqueen operand map
fn cmplog_pass(context: &mut LucidContext) -> Result<(), LucidErr> {
    // Backup the stage
    let backup_stage = context.fuzzing_stage;
    context.fuzzing_stage = FuzzingStage::Cmplog;

    // Turn on Cmplog mode
    let backup_mode = context.cpu_mode;
    context.cpu_mode = CpuMode::Cmplog;

    // Execute the colorized fuzzcase
    fuzz_one(context)?;

    // Reset Bochs' CPU mode
    context.cpu_mode = backup_mode;

    // Restore stage
    context.fuzzing_stage = backup_stage;

    Ok(())
}

/// Converts a vector of bytes to a u8
fn convert_to_u8(bytes: &[u8]) -> u8 {
    let mut buf = [0u8; 1];
    let len = 1;
    buf[..len].copy_from_slice(&bytes[..len]);
    u8::from_ne_bytes(buf)
}

/// Converts a vector of bytes to a u16
fn convert_to_u16(bytes: &[u8]) -> u16 {
    let mut buf = [0u8; 2];
    let len = 2;
    buf[..len].copy_from_slice(&bytes[..len]);
    u16::from_ne_bytes(buf)
}

/// Converts a vector of bytes to a u32
fn convert_to_u32(bytes: &[u8]) -> u32 {
    let mut buf = [0u8; 4];
    let len = 4;
    buf[..len].copy_from_slice(&bytes[..len]);
    u32::from_ne_bytes(buf)
}

/// Converts a vector of bytes to a u64
fn convert_to_u64(bytes: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    let len = 8;
    buf[..len].copy_from_slice(&bytes[..len]);
    u64::from_ne_bytes(buf)
}

/// Converts a vector of bytes to its appropriately sized unsigned integer
/// representation
fn convert_operand(bytes: &[u8]) -> u64 {
    match bytes.len() {
        1 => convert_to_u8(bytes) as u64,
        2 => convert_to_u16(bytes) as u64,
        4 => convert_to_u32(bytes) as u64,
        8 => convert_to_u64(bytes),
        _ => mega_panic!("Bad compare operand size"),
    }
}

/// A heuristic for eliminating compare operations from consideration which are
/// likely to be comparisons for a loop counter
fn remove_loops(context: &mut LucidContext) {
    // Store loop keys here
    let mut loop_keys = Vec::new();

    // Iterate through the operand map looking for loops to remove
    for (rip, operands) in context.redqueen.cmp_operand_map.iter() {
        // If we only have one set of operands, that's not a loop
        if operands.len() <= 1 {
            continue;
        }

        // Get the lhs_0 and rhs_0 values based on the size of the vector
        let lhs_0 = convert_operand(&operands[0].0);
        let rhs_0 = convert_operand(&operands[0].1);

        // Get the lhs_n and rhs_n values
        let lhs_n = convert_operand(&operands[operands.len() - 1].0);
        let rhs_n = convert_operand(&operands[operands.len() - 1].1);

        // If there is evidence that they are loop compares, add them to removal
        if lhs_n == lhs_0 + (operands.len() - 1) as u64 {
            loop_keys.push(*rip);
            continue;
        }

        if rhs_n == rhs_0 + (operands.len() - 1) as u64 {
            loop_keys.push(*rip);
        }
    }

    // Remove the loop keys
    for key in loop_keys {
        context.redqueen.cmp_operand_map.remove(&key);
    }
}

/// Generates all of the possible encodings we want to consider for a specific
/// size of compare operand, the set of encodings is deduplicated
fn get_encodings(operand: Operand) -> Vec<Encoding> {
    // Store final encodings
    let mut encodings = Vec::new();

    // Create a hash-set of seen encodings
    let mut seen_bytes = HashSet::new();

    // Create a little named closure for ease of use
    let mut add = |enc: Encoding| {
        // Convert encoding to bytes
        let bytes = enc.to_bytes();

        // Skip little encodings
        if bytes.len() < OP_FILTER_SIZE {
            return;
        }

        // If we haven't seen this repr, add it
        if seen_bytes.insert(bytes) {
            encodings.push(enc);
        }
    };

    // Match on the operand type and try adding it to the HashSet
    match operand {
        Operand::U8(val) => {
            add(Encoding::Raw8(val));
            add(Encoding::SignExtend8(val as i8));
            add(Encoding::BeSignExtend8((val as i8).to_be()));
            add(Encoding::ZeroExtend16(val as u16));
            add(Encoding::ZeroExtend32(val as u32));
            add(Encoding::ZeroExtend64(val as u64));
            add(Encoding::SignExtend16(val as i16));
            add(Encoding::SignExtend32(val as i32));
            add(Encoding::SignExtend64(val as i64));
            add(Encoding::BeZeroExtend16((val as u16).to_be()));
            add(Encoding::BeZeroExtend32((val as u32).to_be()));
            add(Encoding::BeZeroExtend64((val as u64).to_be()));
            add(Encoding::BeSignExtend16((val as i16).to_be()));
            add(Encoding::BeSignExtend32((val as i32).to_be()));
            add(Encoding::BeSignExtend64((val as i64).to_be()));
        }
        Operand::U16(val) => {
            add(Encoding::Raw16(val));
            add(Encoding::BeZeroExtend16(val.to_be()));
            add(Encoding::ZeroExtend32(val as u32));
            add(Encoding::ZeroExtend64(val as u64));
            add(Encoding::SignExtend32(val as i32));
            add(Encoding::SignExtend64(val as i64));
            add(Encoding::BeZeroExtend32((val as u32).to_be()));
            add(Encoding::BeZeroExtend64((val as u64).to_be()));
            add(Encoding::BeSignExtend32((val as i32).to_be()));
            add(Encoding::BeSignExtend64((val as i64).to_be()));
            add(Encoding::ZeroReduce8((val & 0xFF) as u8));
            add(Encoding::SignReduce8(val as i8));
            add(Encoding::BeZeroReduce8(((val & 0xFF) as u8).to_be()));
            add(Encoding::BeSignReduce8((val as i8).to_be()));
        }
        Operand::U32(val) => {
            add(Encoding::Raw32(val));
            add(Encoding::BeZeroExtend32(val.to_be()));
            add(Encoding::ZeroExtend64(val as u64));
            add(Encoding::SignExtend64(val as i64));
            add(Encoding::BeZeroExtend64((val as u64).to_be()));
            add(Encoding::BeSignExtend64((val as i64).to_be()));
            add(Encoding::ZeroReduce16((val & 0xFFFF) as u16));
            add(Encoding::SignReduce16(val as i16));
            add(Encoding::BeZeroReduce16(((val & 0xFFFF) as u16).to_be()));
            add(Encoding::BeSignReduce16((val as i16).to_be()));
            add(Encoding::ZeroReduce8((val & 0xFF) as u8));
            add(Encoding::SignReduce8(val as i8));
            add(Encoding::BeZeroReduce8(((val & 0xFF) as u8).to_be()));
            add(Encoding::BeSignReduce8((val as i8).to_be()));
        }
        Operand::U64(val) => {
            add(Encoding::Raw64(val));
            add(Encoding::BeZeroExtend64(val.to_be()));
            add(Encoding::ZeroReduce32((val & 0xFFFFFFFF) as u32));
            add(Encoding::SignReduce32(val as i32));
            add(Encoding::BeZeroReduce32(
                ((val & 0xFFFFFFFF) as u32).to_be(),
            ));
            add(Encoding::BeSignReduce32((val as i32).to_be()));
            add(Encoding::ZeroReduce16((val & 0xFFFF) as u16));
            add(Encoding::SignReduce16(val as i16));
            add(Encoding::BeZeroReduce16(((val & 0xFFFF) as u16).to_be()));
            add(Encoding::BeSignReduce16((val as i16).to_be()));
            add(Encoding::ZeroReduce8((val & 0xFF) as u8));
            add(Encoding::SignReduce8(val as i8));
            add(Encoding::BeZeroReduce8(((val & 0xFF) as u8).to_be()));
            add(Encoding::BeSignReduce8((val as i8).to_be()));
        }
    }

    encodings
}

/// Searches the current input for value passed in the `bytes` slice and returns
/// a vector of offsets in the current input where those values are found
fn pattern_search(input: &[u8], bytes: &[u8]) -> Vec<usize> {
    input
        .windows(bytes.len())
        .enumerate()
        .filter_map(|(i, window)| if window == bytes { Some(i) } else { None })
        .collect()
}

/// Returns an encoded operand value based on the operand value's size and
/// the requested encoding scheme passed in `encoding`
fn get_single_encoding(encoding: Encoding, value: Operand) -> Encoding {
    // Extract the raw value
    let raw_val = match value {
        Operand::U8(val) => val as u64,
        Operand::U16(val) => val as u64,
        Operand::U32(val) => val as u64,
        Operand::U64(val) => val,
    };
    // Apply appropriate encoding to raw value and return the encoding
    match encoding {
        Encoding::Raw8(_) => Encoding::Raw8(raw_val as u8),
        Encoding::Raw16(_) => Encoding::Raw16(raw_val as u16),
        Encoding::Raw32(_) => Encoding::Raw32(raw_val as u32),
        Encoding::Raw64(_) => Encoding::Raw64(raw_val),
        Encoding::ZeroExtend16(_) => Encoding::ZeroExtend16(raw_val as u16),
        Encoding::ZeroExtend32(_) => Encoding::ZeroExtend32(raw_val as u32),
        Encoding::ZeroExtend64(_) => Encoding::ZeroExtend64(raw_val),
        Encoding::SignExtend8(_) => Encoding::SignExtend8(raw_val as i8),
        Encoding::SignExtend16(_) => Encoding::SignExtend16(raw_val as i16),
        Encoding::SignExtend32(_) => Encoding::SignExtend32(raw_val as i32),
        Encoding::SignExtend64(_) => Encoding::SignExtend64(raw_val as i64),
        Encoding::ZeroReduce8(_) => Encoding::ZeroReduce8((raw_val & 0xFF) as u8),
        Encoding::ZeroReduce16(_) => Encoding::ZeroReduce16((raw_val & 0xFFFF) as u16),
        Encoding::ZeroReduce32(_) => Encoding::ZeroReduce32((raw_val & 0xFFFFFFFF) as u32),
        Encoding::SignReduce8(_) => Encoding::SignReduce8(raw_val as i8),
        Encoding::SignReduce16(_) => Encoding::SignReduce16(raw_val as i16),
        Encoding::SignReduce32(_) => Encoding::SignReduce32(raw_val as i32),
        Encoding::BeZeroExtend16(_) => Encoding::BeZeroExtend16((raw_val as u16).to_be()),
        Encoding::BeZeroExtend32(_) => Encoding::BeZeroExtend32((raw_val as u32).to_be()),
        Encoding::BeZeroExtend64(_) => Encoding::BeZeroExtend64(raw_val.to_be()),
        Encoding::BeSignExtend8(_) => Encoding::BeSignExtend8((raw_val as i8).to_be()),
        Encoding::BeSignExtend16(_) => Encoding::BeSignExtend16((raw_val as i16).to_be()),
        Encoding::BeSignExtend32(_) => Encoding::BeSignExtend32((raw_val as i32).to_be()),
        Encoding::BeSignExtend64(_) => Encoding::BeSignExtend64((raw_val as i64).to_be()),
        Encoding::BeZeroReduce8(_) => Encoding::BeZeroReduce8(((raw_val & 0xFF) as u8).to_be()),
        Encoding::BeZeroReduce16(_) => {
            Encoding::BeZeroReduce16(((raw_val & 0xFFFF) as u16).to_be())
        }
        Encoding::BeZeroReduce32(_) => {
            Encoding::BeZeroReduce32(((raw_val & 0xFFFFFFFF) as u32).to_be())
        }
        Encoding::BeSignReduce8(_) => Encoding::BeSignReduce8((raw_val as i8).to_be()),
        Encoding::BeSignReduce16(_) => Encoding::BeSignReduce16((raw_val as i16).to_be()),
        Encoding::BeSignReduce32(_) => Encoding::BeSignReduce32((raw_val as i32).to_be()),
    }
}

/// Replaces the bytes in an field with the patch value at offset
fn patch_field(field: &[u8], offset: usize, patch: &[u8]) -> Vec<u8> {
    let mut new_field = field.to_owned();

    // Ensure we don't go out of bounds
    let end = std::cmp::min(offset + patch.len(), new_field.len());

    // Replace the bytes at the specified offset with the patch
    new_field[offset..end].copy_from_slice(&patch[0..(end - offset)]);

    new_field
}

fn apply_variant(encoding: &Encoding, delta: i64) -> Encoding {
    match encoding {
        Encoding::Raw8(val) => Encoding::Raw8(val.wrapping_add(delta as u8)),
        Encoding::Raw16(val) => Encoding::Raw16(val.wrapping_add(delta as u16)),
        Encoding::Raw32(val) => Encoding::Raw32(val.wrapping_add(delta as u32)),
        Encoding::Raw64(val) => Encoding::Raw64(val.wrapping_add(delta as u64)),
        Encoding::ZeroExtend16(val) => Encoding::ZeroExtend16(val.wrapping_add(delta as u16)),
        Encoding::ZeroExtend32(val) => Encoding::ZeroExtend32(val.wrapping_add(delta as u32)),
        Encoding::ZeroExtend64(val) => Encoding::ZeroExtend64(val.wrapping_add(delta as u64)),
        Encoding::SignExtend8(val) => Encoding::SignExtend8(val.wrapping_add(delta as i8)),
        Encoding::SignExtend16(val) => Encoding::SignExtend16(val.wrapping_add(delta as i16)),
        Encoding::SignExtend32(val) => Encoding::SignExtend32(val.wrapping_add(delta as i32)),
        Encoding::SignExtend64(val) => Encoding::SignExtend64(val.wrapping_add(delta)),
        Encoding::ZeroReduce8(val) => Encoding::ZeroReduce8(val.wrapping_add(delta as u8)),
        Encoding::ZeroReduce16(val) => Encoding::ZeroReduce16(val.wrapping_add(delta as u16)),
        Encoding::ZeroReduce32(val) => Encoding::ZeroReduce32(val.wrapping_add(delta as u32)),
        Encoding::SignReduce8(val) => Encoding::SignReduce8(val.wrapping_add(delta as i8)),
        Encoding::SignReduce16(val) => Encoding::SignReduce16(val.wrapping_add(delta as i16)),
        Encoding::SignReduce32(val) => Encoding::SignReduce32(val.wrapping_add(delta as i32)),
        Encoding::BeZeroExtend16(val) => Encoding::BeZeroExtend16(val.wrapping_add(delta as u16)),
        Encoding::BeZeroExtend32(val) => Encoding::BeZeroExtend32(val.wrapping_add(delta as u32)),
        Encoding::BeZeroExtend64(val) => Encoding::BeZeroExtend64(val.wrapping_add(delta as u64)),
        Encoding::BeSignExtend8(val) => Encoding::BeSignExtend8(val.wrapping_add(delta as i8)),
        Encoding::BeSignExtend16(val) => Encoding::BeSignExtend16(val.wrapping_add(delta as i16)),
        Encoding::BeSignExtend32(val) => Encoding::BeSignExtend32(val.wrapping_add(delta as i32)),
        Encoding::BeSignExtend64(val) => Encoding::BeSignExtend64(val.wrapping_add(delta)),
        Encoding::BeZeroReduce8(val) => Encoding::BeZeroReduce8(val.wrapping_add(delta as u8)),
        Encoding::BeZeroReduce16(val) => Encoding::BeZeroReduce16(val.wrapping_add(delta as u16)),
        Encoding::BeZeroReduce32(val) => Encoding::BeZeroReduce32(val.wrapping_add(delta as u32)),
        Encoding::BeSignReduce8(val) => Encoding::BeSignReduce8(val.wrapping_add(delta as i8)),
        Encoding::BeSignReduce16(val) => Encoding::BeSignReduce16(val.wrapping_add(delta as i16)),
        Encoding::BeSignReduce32(val) => Encoding::BeSignReduce32(val.wrapping_add(delta as i32)),
    }
}

/// Searches for a compare operand (and its encoded values) in the field,
/// if found, it generates the equivalent encoding value for its partner
/// operand (and variants +1, -1) and patches the field so that it can try
/// to solve the comparison
fn process_partners(field: &[u8], k: Operand, v: Operand) -> Vec<Vec<u8>> {
    let mut new_fields = Vec::new();

    // Get all of the deduped encodings for our key value
    let k_encodings = get_encodings(k);

    // Iterate through the encodings for k
    for enc in k_encodings {
        // Get the byte representation of the encoding so we can search for it
        let bytes = enc.to_bytes();

        // Find offsets in the field that have the byte pattern
        let offsets = pattern_search(field, &bytes);

        // If we don't find the pattern just continue
        if offsets.is_empty() {
            continue;
        }

        // Get partner encoding using the same encoding scheme as found
        let base_encoding = get_single_encoding(enc, v);
        let plus_encoding = apply_variant(&base_encoding, 1);
        let minus_encoding = apply_variant(&base_encoding, -1);

        // Patch the field with all variants
        for offset in offsets {
            let base_patch = base_encoding.to_bytes();
            let plus_patch = plus_encoding.to_bytes();
            let minus_patch = minus_encoding.to_bytes();

            new_fields.push(patch_field(field, offset, &base_patch));
            new_fields.push(patch_field(field, offset, &plus_patch));
            new_fields.push(patch_field(field, offset, &minus_patch));
        }
    }

    // Return new fields
    new_fields
}

/// Hash an input with the default hasher
fn hash_input(input: &Vec<u8>) -> u64 {
    let mut hasher = DefaultHasher::new();
    input.hash(&mut hasher);
    hasher.finish()
}

/// Attempts to create a collection of new inputs to try based on the Redqueen
/// algorithm of finding operand values (and their encoded equivalents) in the
/// input space and patching the input with its equivalent partner value to
/// solve the comparison
fn create_redqueen_inputs(context: &mut LucidContext, idx: usize) -> Result<(), LucidErr> {
    // Remove loops from the operand map
    remove_loops(context);

    // Now that we've removed loops, create a new hashmap where each entry
    // is an operand pair
    // (0x1337, 0x4142) becomes 2 map entries
    // > 0x1337: 0x4142
    // > 0x4142: 0x1337
    let mut partner_map: HashMap<Operand, Operand> = HashMap::new();

    // Iterate through hashmap of <RIP, [(operands), ...]
    for (_rip, operands) in context.redqueen.cmp_operand_map.iter() {
        // For each set of operands, create a new entry in the partner map
        for (lhs, rhs) in operands {
            let lhs_val = match lhs.len() {
                1 => Operand::U8(convert_operand(lhs) as u8),
                2 => Operand::U16(convert_operand(lhs) as u16),
                4 => Operand::U32(convert_operand(lhs) as u32),
                8 => Operand::U64(convert_operand(lhs)),
                _ => mega_panic!("Bad operand size"),
            };

            let rhs_val = match rhs.len() {
                1 => Operand::U8(convert_operand(rhs) as u8),
                2 => Operand::U16(convert_operand(rhs) as u16),
                4 => Operand::U32(convert_operand(rhs) as u32),
                8 => Operand::U64(convert_operand(rhs)),
                _ => mega_panic!("Bad operand size"),
            };

            // Create both entries, this also dedupes them lol
            partner_map.insert(lhs_val, rhs_val);
            partner_map.insert(rhs_val, lhs_val);
        }
    }

    // Grab the field we want to look through for patching opportunities
    let search_field = context.mutator.get_redqueen_field(idx)?;

    // Process each partner and try to get a patchset to apply to the current
    // input
    for (k, v) in partner_map.iter() {
        let new_fields = process_partners(&search_field, *k, *v);

        // Take backup of the current input so we know the pristine fields
        let backup_input = context.mutator.get_input();

        // Store each input in the redqueen queue if we haven't tried them
        // before
        for new_field in new_fields {
            // Replace original field with new field for input hashing
            context.mutator.set_redqueen_field(idx, new_field)?;

            // Re-assemble new input based on new field
            context.mutator.reassemble_redqueen_fields()?;

            // Get the current input
            let input = context.mutator.get_input_ref();

            // Hash the input
            let hash = hash_input(input);

            // Check if hash is in our last n inputs
            if context.redqueen.hash_set.contains(&hash) {
                continue;
            }

            // Before we add new hash to hash queue, delete oldest if necessary
            if context.redqueen.hash_queue.len() == HASH_SET_SIZE {
                let oldest_hash = context.redqueen.hash_queue.pop_front().unwrap();

                // Remove from the hash set
                context.redqueen.hash_set.remove(&oldest_hash);
            }

            // Add hash to both the queue and set
            context.redqueen.hash_set.insert(hash);
            context.redqueen.hash_queue.push_back(hash);

            // If we're over the max, remove the oldest entry
            if context.redqueen.test_queue.len() >= TEST_QUEUE_MAX {
                context.redqueen.test_queue.pop_front();
            }

            // Add input to the Redqueen test queue for testing
            context.redqueen.test_queue.push_back(input.to_vec());

            // Reset to backup value before processing next field
            context.mutator.copy_input(&backup_input);
            context.mutator.extract_redqueen_fields();
        }
    }

    Ok(())
}

/// Obtains an execution trace of the current input then colorizes the input
/// by introducing as much randomness to the input as possible without affecting
/// the execution trace. Once colorized, pass the input again to Bochs but have
/// Bochs log all compare operand values by changing the CpuMode to Cmplog. Once
/// compare operand values have been obtained, apply standard Redqueen
/// algorithm to patch input operand value candidate positions with its partner
/// value (and variants)
pub fn redqueen_pass(context: &mut LucidContext) -> Result<(), LucidErr> {
    // Take backup of original input
    let orig_input = context.mutator.get_input();

    // Get the ground truth trace hash
    let mut trace_hash = 0;
    if context.config.colorize {
        (trace_hash, _) = input_trace_hash(context)?;
    }

    // Extract redqueen fields so we get a count
    context.mutator.extract_redqueen_fields();

    // Process each field
    for idx in 0..context.mutator.num_redqueen_fields() {
        // Seperate the input into redqueen fields
        context.mutator.extract_redqueen_fields();

        // If the field is zero length, just skip
        let field = context.mutator.get_redqueen_field(idx)?;
        if field.is_empty() {
            continue;
        }

        // Colorize the input optionally
        if context.config.colorize {
            colorize_input(context, trace_hash, idx)?;
        }

        // Now do a Cmplog pass for the colorized input
        cmplog_pass(context)?;

        // Create new inputs to test
        create_redqueen_inputs(context, idx)?;

        // Reset operand map
        context.redqueen.cmp_operand_map.clear();

        // Restore original input so that the field we changed is reverted
        context.mutator.copy_input(&orig_input);
    }

    Ok(())
}
