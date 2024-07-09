/// This file contains all of the logic necessary to perform Redqueen operations
/// during fuzzing

use std::ops::Range;
use std::collections::{VecDeque, HashSet};

use crate::context::{LucidContext, CpuMode, reset_bochs, run_fuzzcase,
    insert_fuzzcase};
use crate::err::LucidErr;
use crate::{mega_panic, prompt};
use std::collections::HashMap;

// Represents the original value that was reported by Bochs
#[derive(Eq, Hash, PartialEq, Clone, Copy, Debug)]
enum Operand {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
}

// Represents the encoding scheme used to encode the operand values
#[derive(Clone, Copy, Debug)]
enum Encoding {
    ZeroExtend8(u8),
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
    pub fn to_bytes(&self) -> Vec<u8> {
        match *self {
            Encoding::ZeroExtend8(val)      => val.to_ne_bytes().to_vec(),
            Encoding::ZeroExtend16(val)     => val.to_ne_bytes().to_vec(),
            Encoding::ZeroExtend32(val)     => val.to_ne_bytes().to_vec(),
            Encoding::ZeroExtend64(val)     => val.to_ne_bytes().to_vec(),
            Encoding::SignExtend8(val)      => val.to_ne_bytes().to_vec(),
            Encoding::SignExtend16(val)     => val.to_ne_bytes().to_vec(),
            Encoding::SignExtend32(val)     => val.to_ne_bytes().to_vec(),
            Encoding::SignExtend64(val)     => val.to_ne_bytes().to_vec(),
            Encoding::ZeroReduce8(val)      => val.to_ne_bytes().to_vec(),
            Encoding::ZeroReduce16(val)     => val.to_ne_bytes().to_vec(),
            Encoding::ZeroReduce32(val)     => val.to_ne_bytes().to_vec(),
            Encoding::SignReduce8(val)      => val.to_ne_bytes().to_vec(),
            Encoding::SignReduce16(val)     => val.to_ne_bytes().to_vec(),
            Encoding::SignReduce32(val)     => val.to_ne_bytes().to_vec(),
            Encoding::BeZeroExtend16(val)   => val.to_ne_bytes().to_vec(),
            Encoding::BeZeroExtend32(val)   => val.to_ne_bytes().to_vec(),
            Encoding::BeZeroExtend64(val)   => val.to_ne_bytes().to_vec(),
            Encoding::BeSignExtend8(val)    => val.to_ne_bytes().to_vec(),
            Encoding::BeSignExtend16(val)   => val.to_ne_bytes().to_vec(),
            Encoding::BeSignExtend32(val)   => val.to_ne_bytes().to_vec(),
            Encoding::BeSignExtend64(val)   => val.to_ne_bytes().to_vec(),
            Encoding::BeZeroReduce8(val)    => val.to_ne_bytes().to_vec(),
            Encoding::BeZeroReduce16(val)   => val.to_ne_bytes().to_vec(),
            Encoding::BeZeroReduce32(val)   => val.to_ne_bytes().to_vec(),
            Encoding::BeSignReduce8(val)    => val.to_ne_bytes().to_vec(),
            Encoding::BeSignReduce16(val)   => val.to_ne_bytes().to_vec(),
            Encoding::BeSignReduce32(val)   => val.to_ne_bytes().to_vec(),
        }
    }
}

// This represents the mutable state of several data structures that enable us
// to do Redqueen operations
#[derive(Clone)]
pub struct Redqueen {
    // A hashmap that contains the RIP for the compare instruction along with
    // a collection of operand tuples seen at that RIP for a single pass
    // Key: RIP, Value: [(op1, op2), (op1, op2), ...]
    cmp_operand_map: HashMap<usize, Vec<(Vec<u8>, Vec<u8>)>>,

    // A collection of inputs that Redqueen crafted that we need to test
    pub queue: Vec<Vec<u8>>,
}

// This represents the 

impl Redqueen {
    pub fn new() -> Self {
        Redqueen {
            cmp_operand_map: HashMap::new(),
            queue: Vec::new(),
        }
    }

    // Helper function to convert an arbitrarily sized operand to its
    // byte representation in a vec<u8>
    fn usize_to_vec(value: usize, size: usize) -> Vec<u8> {
        let num_bytes = size / 8;
        let mut vec = Vec::new();
        for i in 0..num_bytes {
            vec.push(((value >> (i * 8)) & 0xFF) as u8);
        }

        // Return byte vec repr of value
        vec
    }

    // Stash this set of operands in the cmp_operand_map
    pub fn update_operands(
        &mut self, rip: usize, op1: usize, op2: usize, size: usize) {
        // Create byte reprs for the operands
        let op1 = Self::usize_to_vec(op1, size);
        let op2 = Self::usize_to_vec(op2, size);
        
        // Update the map with the operands, avoiding duplicates
        let operands = self.cmp_operand_map.entry(rip).or_insert_with(Vec::new);
        if !operands.contains(&(op1.clone(), op2.clone())) {
            operands.push((op1, op2));
        }
    }
}

// External function we expose to Bochs so that it can use its compare
// instrumentation to extract compare operands and send them to us for RQ
// passes
pub extern "C" fn lucid_report_cmps(contextp: *mut LucidContext, op1: usize,
    op2: usize, op_size: usize, rip: usize) {
    // We have to make sure this bad boy isn't NULL 
    if !LucidContext::is_valid(contextp) {
        mega_panic!("Invalid context\n");
    }

    // Get the context
    let context = LucidContext::from_ptr_mut(contextp);

    // Update the Redqueen compare operand map 
        context.redqueen.update_operands(rip, op1, op2, op_size);
}

// Little helper function for rng stuff, should not re-use here but whatever
#[inline]
fn random(seed: &mut usize) -> usize {
    // Save off current value
    let curr = *seed;

    // Mutate current state with xorshift for next call
    *seed ^= *seed << 13;
    *seed ^= *seed >> 17;
    *seed ^= *seed << 43;

    // Return saved off value
    curr
}

// Re-run the current input and retrieve its execution trace hash
fn input_trace_hash(context: &mut LucidContext) -> Result<usize, LucidErr> {
    // Change Bochs' CPU mode to hash trace mode
    let backup = context.cpu_mode;
    context.cpu_mode = CpuMode::TraceHash;

    // Re-execute the current input
    run_fuzzcase(context)?;

    // Retrieve the hash
    let hash = context.trace_hash;

    // Clear the hash
    context.trace_hash = 0;

    // Reset Bochs' CPU mode
    context.cpu_mode = backup;

    // Clear the coverage map, we're not using it anyways
    context.coverage.reset();

    Ok(hash)
}

// Randomly add bytes to an input until we get the same trace as we had in the
// original fuzzcase
fn colorize_input(context: &mut LucidContext, orig_hash: usize)
    -> Result<(), LucidErr> {
    // Track our colorized input
    let mut colorized = context.mutator.input.clone();

    // Initialize ranges with the entire input range
    let mut ranges: VecDeque<Range<usize>> = VecDeque::new();
    ranges.push_back(0..context.mutator.input.len());

    // Get an RNG seed
    let mut seed = unsafe { core::arch::x86_64::_rdtsc() as usize };

    // In a loop, try to add as much random bytes to the input as possible.
    // If we get the same execution hash we keep that input around and try to
    // randomize more, so everytime a range doesn't work for us, split it in
    // half and try again.
    // Example for a 64-byte input:
    // 1. Randomizing all 64 bytes changes execution hash
    // 2. We try 0..32 and 32..64
    // 3. 0..32 works for us, save this input and keep iterating on it
    // 4. 32..64 does not work, changes hash, we hadd 32-48 and 48-64 to ranges
    // 5. 32..48 fails, add 32-40 and 40-48 to ranges
    // 6. 48..64 works, save this input and keep iterating on it
    // 7. Continue until there are no more ranges to try
    loop {
        // Make sure we a range to test
        if ranges.is_empty() { break; }

        // Insert the colorized input
        context.mutator.memcpy_input(&colorized);

        // Get the next range to test
        let range = ranges.pop_front().unwrap();

        // Replace the bytes in the range randomly
        for byte in &mut context.mutator.input[range.clone()] {
            *byte = random(&mut seed) as u8;
        }

        // Reset Bochs
        reset_bochs(context)?;

        // Insert the modified input into the target
        insert_fuzzcase(context);

        // Execute the fuzzcase and check the hash
        let new_hash = match input_trace_hash(context) {
            Ok(new_hash) => new_hash,
            Err(e) => {
                return Err(e);
            }
        };

        // If the hashes are equal, update the colorized input
        if new_hash == orig_hash {       
            colorized = context.mutator.input.clone();
        }

        // Hashes didn't match, split up the current range and add the new ones
        else {
            // Handle one-byte range
            if range.end - range.start <= 1 {
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
    
    // Done with the loop, make sure we set our colorized input 
    context.mutator.memcpy_input(&colorized);

    // Success
    Ok(())
}

// Turn the Bochs CPU into Cmplog mode so we can collect operand values
fn cmplog_pass(context: &mut LucidContext) -> Result<(), LucidErr> {
    // Turn on Cmplog mode
    let backup = context.cpu_mode;
    context.cpu_mode = CpuMode::Cmplog;

    // Reset Bochs' state
    reset_bochs(context)?;

    // Insert the fuzzcase (colorized)
    insert_fuzzcase(context);

    // Run the fuzzcase
    run_fuzzcase(context)?;

    // Reset Bochs' CPU mode
    context.cpu_mode = backup;

    // Now that we've collected the compare operands, reset coverage
    context.coverage.reset();

    Ok(())
}

// Helpers for bytes -> int conversions
fn convert_to_u8(bytes: &Vec<u8>) -> u8 {
    let mut buf = [0u8; 1];
    let len = 1;
    buf[..len].copy_from_slice(&bytes[..len]);
    u8::from_ne_bytes(buf)
}

// Helpers for bytes -> int conversions
fn convert_to_u16(bytes: &Vec<u8>) -> u16 {
    let mut buf = [0u8; 2];
    let len = 2;
    buf[..len].copy_from_slice(&bytes[..len]);
    u16::from_ne_bytes(buf)
}

// Helpers for bytes -> int conversions
fn convert_to_u32(bytes: &Vec<u8>) -> u32 {
    let mut buf = [0u8; 4];
    let len = 4;
    buf[..len].copy_from_slice(&bytes[..len]);
    u32::from_ne_bytes(buf)
}

// Helpers for bytes -> int conversions
fn convert_to_u64(bytes: &Vec<u8>) -> u64 {
    let mut buf = [0u8; 8];
    let len = 8;
    buf[..len].copy_from_slice(&bytes[..len]);
    u64::from_ne_bytes(buf)
}

// Function to determine the appropriate conversion based on operand size
fn convert_operand(bytes: &Vec<u8>) -> u64 {
    match bytes.len() {
        1 => convert_to_u8(bytes) as u64,
        2 => convert_to_u16(bytes) as u64,
        4 => convert_to_u32(bytes) as u64,
        8 => convert_to_u64(bytes),
        _ => mega_panic!("Bad compare operand size"),
    }
}

// Remove loops from the operand map by testing to see if lhs_0 + n == lhs_n
// and same applies for rhs
fn remove_loops(context: &mut LucidContext) {
    // Store loop keys here
    let mut loop_keys = Vec::new();

    // Iterate through the operand map looking for loops to remove
    for (rip, operands) in context.redqueen.cmp_operand_map.iter() {
        // If we only have one set of operands, that's not a loop
        if operands.len() <= 1 { continue; }

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

// Generate all encodings for an operand type
fn get_encodings(operand: Operand) -> Vec<Encoding> {
    let mut encodings = Vec::new();

    // Match on the operand type
    match operand {
        Operand::U8(val) => {
            encodings.push(Encoding::ZeroExtend8(val));  // Original
            encodings.push(Encoding::SignExtend8(val as i8));
            encodings.push(Encoding::BeSignExtend8((val as i8).to_be()));
            encodings.push(Encoding::ZeroExtend16(val as u16));
            encodings.push(Encoding::ZeroExtend32(val as u32));
            encodings.push(Encoding::ZeroExtend64(val as u64));
            encodings.push(Encoding::SignExtend16(val as i16));
            encodings.push(Encoding::SignExtend32(val as i32));
            encodings.push(Encoding::SignExtend64(val as i64));
            encodings.push(Encoding::BeZeroExtend16((val as u16).to_be()));
            encodings.push(Encoding::BeZeroExtend32((val as u32).to_be()));
            encodings.push(Encoding::BeZeroExtend64((val as u64).to_be()));
            encodings.push(Encoding::BeSignExtend16((val as i16).to_be()));
            encodings.push(Encoding::BeSignExtend32((val as i32).to_be()));
            encodings.push(Encoding::BeSignExtend64((val as i64).to_be()));
        },
        Operand::U16(val) => {
            encodings.push(Encoding::ZeroExtend16(val));  // Original
            encodings.push(Encoding::BeZeroExtend16(val.to_be())); // BE orig
            encodings.push(Encoding::ZeroExtend32(val as u32));
            encodings.push(Encoding::ZeroExtend64(val as u64));
            encodings.push(Encoding::SignExtend32(val as i32));
            encodings.push(Encoding::SignExtend64(val as i64));
            encodings.push(Encoding::BeZeroExtend32((val as u32).to_be()));
            encodings.push(Encoding::BeZeroExtend64((val as u64).to_be()));
            encodings.push(Encoding::BeSignExtend32((val as i32).to_be()));
            encodings.push(Encoding::BeSignExtend64((val as i64).to_be()));
            encodings.push(Encoding::ZeroReduce8((val & 0xFF) as u8));
            encodings.push(Encoding::SignReduce8(val as i8));
            encodings.push(Encoding::BeZeroReduce8(((val & 0xFF) as u8).to_be()));
            encodings.push(Encoding::BeSignReduce8((val as i8).to_be()));
        },
        Operand::U32(val) => {
            encodings.push(Encoding::ZeroExtend32(val));  // Original
            encodings.push(Encoding::BeZeroExtend32(val.to_be())); // BE orig
            encodings.push(Encoding::ZeroExtend64(val as u64));
            encodings.push(Encoding::SignExtend64(val as i64));
            encodings.push(Encoding::BeZeroExtend64((val as u64).to_be()));
            encodings.push(Encoding::BeSignExtend64((val as i64).to_be()));
            encodings.push(Encoding::ZeroReduce16((val & 0xFFFF) as u16));
            encodings.push(Encoding::SignReduce16(val as i16));
            encodings.push(Encoding::BeZeroReduce16(((val & 0xFFFF) as u16).to_be()));
            encodings.push(Encoding::BeSignReduce16((val as i16).to_be()));
            encodings.push(Encoding::ZeroReduce8((val & 0xFF) as u8));
            encodings.push(Encoding::SignReduce8(val as i8));
            encodings.push(Encoding::BeZeroReduce8(((val & 0xFF) as u8).to_be()));
            encodings.push(Encoding::BeSignReduce8((val as i8).to_be()));
        },
        Operand::U64(val) => {
            encodings.push(Encoding::ZeroExtend64(val));  // Original
            encodings.push(Encoding::BeZeroExtend64(val.to_be())); // BE orig
            encodings.push(Encoding::ZeroReduce32((val & 0xFFFFFFFF) as u32));
            encodings.push(Encoding::SignReduce32(val as i32));
            encodings.push(Encoding::BeZeroReduce32(((val & 0xFFFFFFFF) as u32).to_be()));
            encodings.push(Encoding::BeSignReduce32((val as i32).to_be()));
            encodings.push(Encoding::ZeroReduce16((val & 0xFFFF) as u16));
            encodings.push(Encoding::SignReduce16(val as i16));
            encodings.push(Encoding::BeZeroReduce16(((val & 0xFFFF) as u16).to_be()));
            encodings.push(Encoding::BeSignReduce16((val as i16).to_be()));
            encodings.push(Encoding::ZeroReduce8((val & 0xFF) as u8));
            encodings.push(Encoding::SignReduce8(val as i8));
            encodings.push(Encoding::BeZeroReduce8(((val & 0xFF) as u8).to_be()));
            encodings.push(Encoding::BeSignReduce8((val as i8).to_be()));
        },
    }

    encodings
}

// Search the input for the byte pattern, return vector of offsets 
fn pattern_search(input: &[u8], bytes: &[u8]) -> Vec<usize> {
    input.windows(bytes.len())
            .enumerate()
            .filter_map(|(i, window)| if window == bytes {
                Some(i) 
            } else {
                None
            }).collect()
}

// Return variants for a partner
fn get_partner_variants(value: Operand) -> (Operand, Operand, Operand) {
    // Match on the operand type and create encodings for the variant values
    let (val1, val2, val3) = match value {
        Operand::U8(val) => (
            Operand::U8(val),
            Operand::U8(val.wrapping_add(1)),
            Operand::U8(val.wrapping_sub(1))
        ),
        Operand::U16(val) => (
            Operand::U16(val),
            Operand::U16(val.wrapping_add(1)),
            Operand::U16(val.wrapping_sub(1))
        ),
        Operand::U32(val) => (
            Operand::U32(val),
            Operand::U32(val.wrapping_add(1)),
            Operand::U32(val.wrapping_sub(1))
        ),
        Operand::U64(val) => (
            Operand::U64(val),
            Operand::U64(val.wrapping_add(1)),
            Operand::U64(val.wrapping_sub(1))
        ),
    };

    (val1, val2, val3)
}

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
        Encoding::ZeroExtend8(_)    =>
            Encoding::ZeroExtend8(raw_val as u8),
        Encoding::ZeroExtend16(_)   =>
            Encoding::ZeroExtend16(raw_val as u16),
        Encoding::ZeroExtend32(_)   =>
            Encoding::ZeroExtend32(raw_val as u32),
        Encoding::ZeroExtend64(_)   =>
            Encoding::ZeroExtend64(raw_val),
        Encoding::SignExtend8(_)    =>
            Encoding::SignExtend8(raw_val as i8),
        Encoding::SignExtend16(_)   =>
            Encoding::SignExtend16(raw_val as i16),
        Encoding::SignExtend32(_)   =>
            Encoding::SignExtend32(raw_val as i32),
        Encoding::SignExtend64(_)   =>
            Encoding::SignExtend64(raw_val as i64),
        Encoding::ZeroReduce8(_)    =>
            Encoding::ZeroReduce8((raw_val & 0xFF) as u8),
        Encoding::ZeroReduce16(_)   =>
            Encoding::ZeroReduce16((raw_val & 0xFFFF) as u16),
        Encoding::ZeroReduce32(_)   =>
            Encoding::ZeroReduce32((raw_val & 0xFFFFFFFF) as u32),
        Encoding::SignReduce8(_)    =>
            Encoding::SignReduce8(raw_val as i8),
        Encoding::SignReduce16(_)   =>
            Encoding::SignReduce16(raw_val as i16),
        Encoding::SignReduce32(_)   =>
            Encoding::SignReduce32(raw_val as i32),
        Encoding::BeZeroExtend16(_) =>
            Encoding::BeZeroExtend16((raw_val as u16).to_be()),
        Encoding::BeZeroExtend32(_) =>
            Encoding::BeZeroExtend32((raw_val as u32).to_be()),
        Encoding::BeZeroExtend64(_) =>
            Encoding::BeZeroExtend64(raw_val.to_be()),
        Encoding::BeSignExtend8(_)  =>
            Encoding::BeSignExtend8((raw_val as i8).to_be()),
        Encoding::BeSignExtend16(_) =>
            Encoding::BeSignExtend16((raw_val as i16).to_be()),
        Encoding::BeSignExtend32(_) =>
            Encoding::BeSignExtend32((raw_val as i32).to_be()),
        Encoding::BeSignExtend64(_) =>
            Encoding::BeSignExtend64((raw_val as i64).to_be()),
        Encoding::BeZeroReduce8(_)  =>
            Encoding::BeZeroReduce8(((raw_val & 0xFF) as u8).to_be()),
        Encoding::BeZeroReduce16(_) =>
            Encoding::BeZeroReduce16(((raw_val & 0xFFFF) as u16).to_be()),
        Encoding::BeZeroReduce32(_) =>
            Encoding::BeZeroReduce32(((raw_val & 0xFFFFFFFF) as u32).to_be()),
        Encoding::BeSignReduce8(_)  =>
            Encoding::BeSignReduce8((raw_val as i8).to_be()),
        Encoding::BeSignReduce16(_) =>
            Encoding::BeSignReduce16((raw_val as i16).to_be()),
        Encoding::BeSignReduce32(_) =>
            Encoding::BeSignReduce32((raw_val as i32).to_be()),
    }
}

fn get_partner_encodings(encoding: Encoding, value: Operand) -> Vec<Encoding> {
    let mut encodings = Vec::new();

    // Match on the operand type and create encodings for the variant values
    let (var1, var2, var3) = get_partner_variants(value);

    // Iterate through the variants and get encodings for each
    for var in &[var1, var2, var3] {
        encodings.push(get_single_encoding(encoding, *var));
    }

    encodings
}

// Fix up an input with a patch
fn patch_input(input: &Vec<u8>, offset: usize, patch: &[u8]) -> Vec<u8> {
    let mut new_input = input.clone();
    
    // Ensure we don't go out of bounds
    let end = std::cmp::min(offset + patch.len(), new_input.len());
    
    // Replace the bytes at the specified offset with the patch
    new_input[offset..end].copy_from_slice(&patch[0..(end - offset)]);
    
    new_input
}

// Process a partner pair and return a collection of new inputs to test
fn process_partners(input: &Vec<u8>, k: Operand, v: Operand) -> Vec<Vec<u8>> {
    let mut new_inputs = Vec::new();

    // Get all of the encodings for our key value
    let k_encodings = get_encodings(k);

    // Iterate through the encodings for k
    for enc in k_encodings {

        // Get the byte representation of the encoding so we can search for it
        let bytes = enc.to_bytes();

        // Find offsets in the input that have the byte pattern
        let offsets = pattern_search(input, &bytes);

        // If we don't find the pattern just continue
        if offsets.is_empty() {
            continue;
        }

        // If we have offsets, get encoding values for the key's partner
        let partner_encs = get_partner_encodings(enc, v);

        // Dedupe encodings at byte level
        let mut partner_bytes = HashSet::new();
        for partner_enc in partner_encs {
            partner_bytes.insert(partner_enc.to_bytes());
        }

        // Patch the input
        for offset in offsets {
            for partner_byte in &partner_bytes {
                new_inputs.push(
                    patch_input(input, offset, &partner_byte));
            }
        }
    }

    // Return new inputs
    new_inputs
}

// Use our logged compare operands to create new inputs to test by inserting
// them into the redqueen queue
fn create_redqueen_inputs(context: &mut LucidContext) {
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
                1 => { Operand::U8(convert_operand(lhs) as u8) },
                2 => { Operand::U16(convert_operand(lhs) as u16) },
                4 => { Operand::U32(convert_operand(lhs) as u32) },
                8 => { Operand::U64(convert_operand(lhs) as u64) },
                _ => mega_panic!("Bad operand size"),
            };

            let rhs_val = match rhs.len() {
                1 => { Operand::U8(convert_operand(rhs) as u8) },
                2 => { Operand::U16(convert_operand(rhs) as u16) },
                4 => { Operand::U32(convert_operand(rhs) as u32) },
                8 => { Operand::U64(convert_operand(rhs) as u64) },
                _ => mega_panic!("Bad operand size"),
            };
            
            // Create both entries, this also dedupes them lol
            partner_map.insert(lhs_val, rhs_val);
            partner_map.insert(rhs_val, lhs_val);
        }
    }

    // Process each partner and try to get a patchset to apply to the current
    // input
    for (k, v) in partner_map.iter() {
        let inputs = process_partners(&context.mutator.input, *k, *v);

        let num_inputs = inputs.len();
        
        // Store each input in the redqueen queue
        for input in inputs {
            context.redqueen.queue.push(input);
        }

        // Notify user
        if num_inputs > 0 {
            prompt!("Redqueen added {} inputs to queue ({} total)",
                num_inputs, context.redqueen.queue.len());
        }
    }
}

// Perform a Redqueen pass in an effort to improve coverage of a new input
pub fn redqueen_pass(context: &mut LucidContext) -> Result<(), LucidErr> {
    // Reset Bochs' state
    reset_bochs(context)?;

    // Insert fuzzcase
    insert_fuzzcase(context);

    // Obtain the trace hash for the current input
    let trace_hash = input_trace_hash(context)?;

    // Colorize the input
    colorize_input(context, trace_hash)?;

    // Now do a Cmplog pass for the colorized input
    cmplog_pass(context)?;

    // Create new inputs to test
    create_redqueen_inputs(context);

    // Clear the compare operand map now that we've done our pass and added
    // inputs to the queue
    context.redqueen.cmp_operand_map.clear();

    Ok(())
}