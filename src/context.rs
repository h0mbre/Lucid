/// This file contains the logic necessary to perform context-switching between
/// Lucid and Bochs
///
/// The calling convention we use for context switching:
/// r15 -- Pointer to a LucidContext
use std::arch::{asm, global_asm};

use crate::config::Config;
use crate::corpus::Corpus;
use crate::coverage::CoverageMap;
use crate::err::LucidErr;
use crate::files::FileTable;
use crate::loader::Bochs;
use crate::misc::{fxrstor64, fxsave64, get_xcr0, xrstor64, xsave64};
use crate::mmu::Mmu;
use crate::mutator::Mutator;
use crate::redqueen::{lucid_report_cmps, redqueen_pass, Redqueen};
use crate::snapshot::{restore_snapshot, take_snapshot, Snapshot};
use crate::stats::Stats;
use crate::syscall::lucid_syscall;
use crate::{fault, mega_panic, prompt, prompt_warn};

// Duh
const PAGE_SIZE: usize = 0x1000;

// Magic number member of the LucidContext, chosen by ChatGPT
pub const CTX_MAGIC: usize = 0x74DFF25D576D6F4D;

// Length of scratch stack
const SCRATCH_STACK_LEN: usize = 0x21000;

// Default timeout for instruction count in a fuzzcase
const DEFAULT_ICOUNT_TIMEOUT: usize = 250_000_000;

// This represents the reason why a VM has exited execution and is now trying
// to context-switch for event handling
#[derive(Clone, Copy, Debug)]
pub enum VmExit {
    NoExit = 0,
    StartBochs = 1,
    TakeSnapshot = 2,
    PostFuzzHook = 3,
    ResumeBochs = 4,
}

// We get passed an i32, have to go through this to get a Rust enum
impl TryFrom<i32> for VmExit {
    // Dummy error
    type Error = ();

    // Return value or error
    fn try_from(val: i32) -> Result<Self, Self::Error> {
        match val {
            1 => Ok(VmExit::StartBochs),
            2 => Ok(VmExit::TakeSnapshot),
            3 => Ok(VmExit::PostFuzzHook),
            4 => Ok(VmExit::ResumeBochs),
            _ => Err(()),
        }
    }
}

// The kind of extended state saving instruction we need to use based on our
// processor
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SaveInst {
    NoSave = 0,
    XSave64 = 1,
    FxSave64 = 2,
}

// We get passed an i32 from Bochs, have to go through this to get a Rust enum
impl TryFrom<i32> for SaveInst {
    // Dummy error
    type Error = ();

    // Return value or error
    fn try_from(val: i32) -> Result<Self, Self::Error> {
        match val {
            0 => Ok(SaveInst::NoSave),
            1 => Ok(SaveInst::XSave64),
            2 => Ok(SaveInst::FxSave64),
            _ => Err(()),
        }
    }
}

// Modes of execution, either Bochs or Lucid
#[repr(i32)]
#[derive(Copy, Clone)]
pub enum ExecMode {
    Bochs = 0, // We exited from Bochs
    Lucid = 1, // We exited from Lucid
}

// We get passed an i32, have to go through this to get a Rust enum
impl TryFrom<i32> for ExecMode {
    // Dummy error
    type Error = ();

    // Return value or error
    fn try_from(val: i32) -> Result<Self, Self::Error> {
        match val {
            0 => Ok(ExecMode::Bochs),
            1 => Ok(ExecMode::Lucid),
            _ => Err(()),
        }
    }
}

// We have to abstract away and sandbox TLS access from Bochs, so when Bochs
// asks for TLS, we give it a pointer to this struct which is an inline member
// of LucidContext. This is modeled directly after `builtin_tls` in __init_tls.c
//
// static struct builtin_tls {
//	char c;
//	struct pthread pt;
//	void *space[16];
//} builtin_tls[1];
//
// pthread_t is 200 bytes; errno is at offset 52
#[repr(C)]
#[derive(Clone)]
pub struct Tls {
    padding0: [u8; 8],  // char c
    padding1: [u8; 52], // Padding to offset of errno which is 52-bytes
    pub errno: i32,
    padding2: [u8; 144], // Additional padding to get to 200-bytes total
    padding3: [u8; 128], // 16 void * values
}

impl Tls {
    fn new() -> Self {
        Tls {
            padding0: [0; 8],
            padding1: [0; 52],
            errno: 0,
            padding2: [0; 144],
            padding3: [0; 128],
        }
    }
}

// Just memory we save GPRs to when we context switch
#[repr(C)]
#[derive(Default, Clone)]
pub struct RegisterBank {
    pub rax: usize,
    rbx: usize,
    rcx: usize,
    pub rdx: usize,
    pub rsi: usize,
    pub rdi: usize,
    rbp: usize,
    rsp: usize,
    pub r8: usize,
    pub r9: usize,
    pub r10: usize,
    r11: usize,
    r12: usize,
    r13: usize,
    r14: usize,
    r15: usize,
}

// This determines how Bochs handles instructions when its simulating them
#[repr(C)]
#[derive(Clone, Copy)]
pub enum CpuMode {
    Fuzzing = 0,
    Cmplog = 1,
    TraceHash = 2,
}

// Represents the different kinds of fuzzing stages we can have
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum FuzzingStage {
    NotFuzzing,
    DryRun,
    Fuzzing,
    Cmplog,
    Colorization,
    Redqueen,
}

impl std::fmt::Display for FuzzingStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FuzzingStage::NotFuzzing => write!(f, "Not Fuzzing"),
            FuzzingStage::DryRun => write!(f, "Dry Run"),
            FuzzingStage::Fuzzing => write!(f, "Fuzzing"),
            FuzzingStage::Cmplog => write!(f, "Cmplog"),
            FuzzingStage::Colorization => write!(f, "Colorization"),
            FuzzingStage::Redqueen => write!(f, "Redqueen"),
        }
    }
}

// Represents the outcome of a fuzzing iteration
#[derive(Debug, PartialEq)]
pub enum FuzzingResult {
    None,
    Crash,
    Timeout,
    NewCoverage,
}

// Execution context that is passed between Lucid and Bochs that tracks
// all of the mutable state information we need to do context-switching
#[repr(C)]
#[derive(Clone)]
pub struct LucidContext {
    /* These cannot change order, context_switch depends on them */
    pub context_switch: usize,    // Address of context_switch()
    exec_mode: ExecMode,          // Our current mode of execution
    lucid_regs: RegisterBank,     // Holds Lucid register state for GPRs
    pub bochs_regs: RegisterBank, // Holds Bochs register state for GPRs
    pub scratch_rsp: usize,       // Stack pointer for the scratch stack
    lucid_syscall: usize,         // Address of lucid_syscall()
    lucid_report_cmps: usize,     // Address of lucid_report_cmps()

    /* Defined on C side */
    pub tls: Tls,             // Bochs' TLS instance
    pub fs_reg: usize,        // The %fs reg value that we're faking
    exit_reason: VmExit,      // Why we're context switching
    coverage_map_addr: usize, // Address of the coverage map buffer
    coverage_map_size: usize, // Size of the coverage map in members
    pub trace_hash: usize,    // Hash for all PCs taken during input
    crash: i32,               // Did we have a crash? Set by Bochs side
    timeout: i32,             // Did we have a timeout? Set by Bochs side
    icount_timeout: usize,    // Instruction count we use as timeout barrier
    pub cpu_mode: CpuMode,    // The current Bochs CPU mode

    /* Opaque members, not defined on C side */
    pub save_inst: SaveInst,    // Type of save instruction we use for exstate
    pub save_size: usize,       // Size of the save area
    pub lucid_save_area: usize, // Pointer to the save area for Lucid
    pub bochs_save_area: usize, // Pointer to the save area for Bochs
    pub bochs: Bochs,           // The Bochs image
    pub magic: usize,           // Magic value for debugging purposes
    pub mmu: Mmu,               // Bochs' memory manager
    pub clock_time: usize,      // Nanoseconds
    pub files: FileTable,       // Bochs' files
    pub err: Option<LucidErr>,  // Current erro if there is one for faults
    pub verbose: bool,          // Are we printing Bochs output
    pub fuzzing: bool,          // Status flag to track file dirtying
    pub dirty_files: bool,      // Did we dirty any files during fuzzing?
    pub snapshot: Snapshot,     // The Bochs snapshot
    pub stats: Stats,           // Fuzzing stats
    pub coverage: CoverageMap,  // The coverage map
    pub input_size_addr: usize, // The memory address of the input size variable
    pub input_buf_addr: usize,  // The memory address of the input buf variable
    pub mutator: Mutator,       // Mutator we're using
    pub redqueen: Redqueen,     // Redqueen state
    pub config: Config,         // Configuration based on user options
    pub corpus: Corpus,         // Inputs
    pub fuzzing_stage: FuzzingStage, // Dictates logic for running inputs
}

impl LucidContext {
    // Static method to check if a contextp is sane
    pub fn is_valid(contextp: *mut LucidContext) -> bool {
        if contextp.is_null() {
            return false;
        }

        let context = unsafe { &*contextp };

        // Check the magic value
        if context.magic != CTX_MAGIC {
            return false;
        }

        if SaveInst::try_from(context.save_inst as i32).is_err() {
            return false;
        }

        // Ensure ExecMode conversion succeeds
        if ExecMode::try_from(context.exec_mode as i32).is_err() {
            return false;
        }

        // Ensure VmExit conversion succeeds
        if VmExit::try_from(context.exit_reason as i32).is_err() {
            return false;
        }

        true
    }

    // Get a non-mutable context reference from a raw pointer
    #[inline]
    pub fn from_ptr(contextp: *mut LucidContext) -> &'static LucidContext {
        unsafe { &*contextp }
    }

    // Get a mutable context reference from raw pointer
    #[inline]
    pub fn from_ptr_mut(contextp: *mut LucidContext) -> &'static mut LucidContext {
        unsafe { &mut *contextp }
    }

    #[inline]
    pub fn is_lucid_mode(&self) -> bool {
        matches!(self.exec_mode, ExecMode::Lucid)
    }

    #[inline]
    pub fn _is_bochs_mode(&self) -> bool {
        matches!(self.exec_mode, ExecMode::Bochs)
    }

    // Get the address of the save area based on our current ExecMode
    #[inline]
    pub fn get_save_area(&self) -> usize {
        match self.exec_mode {
            ExecMode::Bochs => self.bochs_save_area,
            ExecMode::Lucid => self.lucid_save_area,
        }
    }

    // Return pointer to the Lucid register bank
    #[inline]
    pub fn lucid_regs_ptr(&self) -> *const RegisterBank {
        &self.lucid_regs as *const RegisterBank
    }

    // Return pointer to the Bochs register bank
    #[inline]
    pub fn snapshot_regs_ptr(&self) -> *const RegisterBank {
        &self.snapshot.regs as *const RegisterBank
    }

    // Save the extended state
    pub fn save_xstate(&self) {
        // Check if there is saving
        if self.save_inst == SaveInst::NoSave {
            return;
        }

        // Make sure there's save area
        if self.lucid_save_area == 0 || self.bochs_save_area == 0 {
            return;
        }

        // Determine save area based on execution mode
        let save_area = self.get_save_area();

        // Do the saving
        match self.save_inst {
            SaveInst::XSave64 => {
                let xcr0 = get_xcr0();
                xsave64(save_area as *mut u8, xcr0);
            }
            SaveInst::FxSave64 => {
                fxsave64(save_area as *mut u8);
            }
            _ => unreachable!(), // NoSave
        }
    }

    pub fn restore_xstate(&self) {
        // Check if there is saving
        if self.save_inst == SaveInst::NoSave {
            return;
        }

        // Make sure there's save area
        if self.lucid_save_area == 0 || self.bochs_save_area == 0 {
            return;
        }

        // Determine save area based on execution mode
        let save_area = self.get_save_area();

        // Restore
        match self.save_inst {
            SaveInst::XSave64 => {
                let xcr0 = get_xcr0();
                xrstor64(save_area as *const u8, xcr0);
            }
            SaveInst::FxSave64 => {
                fxrstor64(save_area as *const u8);
            }
            _ => unreachable!(), // NoSave
        }
    }

    // Check if we're fuzzing or not
    #[inline]
    pub fn is_fuzzing(&self) -> bool {
        self.fuzzing
    }

    // Only ever called from main.rs
    pub fn new(bochs: Bochs, config: &Config, corpus: Corpus) -> Result<Self, LucidErr> {
        // Check for what kind of features are supported we check from most
        // advanced to least
        let save_inst = if std::is_x86_feature_detected!("xsave") {
            SaveInst::XSave64
        } else if std::is_x86_feature_detected!("fxsr") {
            SaveInst::FxSave64
        } else {
            SaveInst::NoSave
        };

        // Get save area size
        let save_size: usize = match save_inst {
            SaveInst::NoSave => 0,
            _ => calc_save_size(),
        };

        // If we have to save, let's map some memory to save the extended
        // state for the fuzzer and Bochs
        let (lucid_save_area, bochs_save_area) = match save_inst {
            SaveInst::NoSave => (0, 0),
            _ => map_save_areas(save_size, &bochs)?,
        };

        // Calculate the boundary of the save area
        let initial_boundary = bochs.write_base + bochs.write_length + (save_size * 2);

        // Create an MMU
        let mmu = Mmu::new(initial_boundary)?;

        // Get the new boundary
        let final_boundary = initial_boundary + mmu.map_length;

        // Get the snapshot area base and length
        let snapshot_base = bochs.write_base;
        let snapshot_length = final_boundary - snapshot_base;

        // Create an empty snapshot but then initialize the information about
        // the snapshot dimensions
        let mut snapshot = Snapshot::default();
        snapshot.base = snapshot_base;
        snapshot.length = snapshot_length;

        // Create scratch stack
        let scratch_stack_base = create_scratch_stack()?;

        // Set the stack pointer
        let scratch_rsp = scratch_stack_base + SCRATCH_STACK_LEN - PAGE_SIZE;

        // Create coverage map
        let coverage = CoverageMap::new();
        let coverage_map_addr = coverage.addr();
        let coverage_map_size = coverage.curr_map.len();

        // Create mutator
        let mutator = Mutator::new(config.mutator_seed, config.input_max_size);

        // Create a timeout
        let icount_timeout = match config.icount_timeout {
            None => {
                prompt_warn!(
                    "No icount timeout specified, defaulting to {}M instructions",
                    DEFAULT_ICOUNT_TIMEOUT / 1_000_000
                );
                DEFAULT_ICOUNT_TIMEOUT
            }
            Some(val) => val,
        };

        // Build and return the execution context so we can fuzz!
        Ok(LucidContext {
            context_switch: context_switch as usize,
            exec_mode: ExecMode::Lucid,
            exit_reason: VmExit::NoExit,
            scratch_rsp,
            lucid_syscall: lucid_syscall as usize,
            lucid_report_cmps: lucid_report_cmps as usize,
            save_inst,
            save_size,
            lucid_save_area,
            bochs_save_area,
            lucid_regs: RegisterBank::default(),
            bochs_regs: RegisterBank::default(),
            bochs,
            tls: Tls::new(),
            magic: CTX_MAGIC,
            fs_reg: 0,
            mmu,
            clock_time: 0,
            files: FileTable::new(),
            err: None,
            verbose: config.verbose,
            fuzzing: false,
            dirty_files: false,
            snapshot,
            stats: Stats::new(config),
            coverage,
            coverage_map_addr,
            coverage_map_size,
            trace_hash: 0,
            input_size_addr: 0,
            input_buf_addr: 0,
            mutator,
            crash: 0,
            timeout: 0,
            icount_timeout,
            redqueen: Redqueen::new(),
            cpu_mode: CpuMode::Fuzzing,
            config: config.clone(),
            corpus,
            fuzzing_stage: FuzzingStage::NotFuzzing,
        })
    }
}

fn create_scratch_stack() -> Result<usize, LucidErr> {
    let result = unsafe {
        libc::mmap(
            std::ptr::null_mut::<libc::c_void>(),
            SCRATCH_STACK_LEN,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
            -1,
            0,
        )
    };

    if result == libc::MAP_FAILED {
        return Err(LucidErr::from("Failed to mmap scratch stack"));
    }

    Ok(result as usize)
}

// Standalone function to calculate the size of the save area for saving the
// extended processor state based on the current processor's features. `cpuid`
// will return the save area size based on the value of the XCR0 when ECX==0
// and EAX==0xD. The value returned to EBX is based on the current features
// enabled in XCR0, while the value returned in ECX is the largest size it
// could be based on CPU capabilities. So out of an abundance of caution we use
// the ECX value. We have to preserve EBX or rustc gets angry at us. We are
// assuming that the fuzzer and Bochs do not modify the XCR0 at any time.
fn calc_save_size() -> usize {
    let save: usize;
    unsafe {
        asm!(
            "push rbx",
            "mov rax, 0xD",
            "xor rcx, rcx",
            "cpuid",
            "pop rbx",
            out("rax") _,       // Clobber
            out("rcx") save,    // Save the max size
            out("rdx") _,       // Clobbered by CPUID output (w EAX)
        );
    }

    // Round up to the nearest page size
    (save + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

// Standalone function that just maps pages for the extended state save area,
// for both Lucid and Bochs, these are mapped contiguously with our Bochs
// image and the Bochs stack
fn map_save_areas(size: usize, bochs: &Bochs) -> Result<(usize, usize), LucidErr> {
    assert!(size % PAGE_SIZE == 0);

    // Determine where we're mapping this writable memory
    let map_addr = bochs.write_base + bochs.write_length;

    // Calculate the total size needed
    let total_size = size * 2;

    // Perform the mmap operation
    let result = unsafe {
        libc::mmap(
            map_addr as *mut libc::c_void,
            total_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE | libc::MAP_FIXED,
            -1,
            0,
        )
    };

    if result == libc::MAP_FAILED || result != map_addr as *mut libc::c_void {
        return Err(LucidErr::from("Failed mmap memory for xsave area"));
    }

    // Return the two addresses
    Ok((map_addr, map_addr + size))
}

// Start Bochs execution by providing a stack and jumping to entry
// RDX must be cleared as otherwise it will set exit hooks
// R15 must point to LucidContext as per our calling convention
fn jump_to_bochs(contextp: *mut LucidContext) {
    // Get the read-only reference to the context
    let context = LucidContext::from_ptr(contextp);
    let rsp = context.bochs.rsp;
    let entry = context.bochs.entry;

    unsafe {
        asm!(
            "xor rdx, rdx",
            "mov rsp, {0}",
            "mov r15, {1}",
            "jmp rax",
            in(reg) rsp,
            in(reg) contextp,
            in("rax") entry,
            lateout("rax") _,   // Clobber (inout so no conflict with in)
            out("rdx") _,       // Clobber
            out("r15") _,       // Clobber
        );
    }
}

// This is where the actual logic is for handling the Lucid/Bochs exits, we have
// to use no_mangle here so that we can call it from the assembly blob. We need
// to see why we've exited and dispatch to the appropriate function. This is the
// only place thus far where we do comprehensive sanity checks on the context
// pointer.
#[no_mangle]
fn switch_handler(contextp: *mut LucidContext) {
    // We have to make sure this bad boy isn't NULL
    if !LucidContext::is_valid(contextp) {
        mega_panic!("Invalid context\n");
    }

    // Get read-only context
    let context = LucidContext::from_ptr(contextp);

    // Before we do anything else, save the extended state
    context.save_xstate();

    // Try to get the VmExit reason
    let exit_reason = context.exit_reason;

    // Handle Lucid context switches here
    if context.is_lucid_mode() {
        match exit_reason {
            // Dispatch to Bochs entry point
            VmExit::StartBochs => {
                jump_to_bochs(contextp);
            }
            VmExit::ResumeBochs => {
                restore_bochs_execution(contextp);
            }
            _ => {
                fault!(contextp, LucidErr::from("Bad Lucid exit"));
            }
        }
    }
    // Handle Bochs context switches here
    else {
        match exit_reason {
            // Take a snapshot of Bochs
            VmExit::TakeSnapshot => {
                take_snapshot(contextp);

                // Come back to Lucid
                restore_lucid_execution(contextp);
            }
            // Complete a fuzzing iteration
            VmExit::PostFuzzHook => {
                restore_lucid_execution(contextp);
            }
            _ => {
                fault!(contextp, LucidErr::from("Bad Bochs exit"));
            }
        }
    }

    // Restore extended state
    context.restore_xstate();
}

// This is our context_switch function, this stub is meant to save as much state
// as necessary before we can start calling regular Rust functions, right now it
// saves the CPU flags and the GPRs and then switches to a 'scratch stack' that
// we use during context switch higher-level logic before calling into
// `switch_handler`.
extern "C" {
    fn context_switch();
}
global_asm!(
    ".global context_switch",
    "context_switch:",
    // Save the CPU flags before we do any operations
    "pushfq",
    // Save registers we use for scratch
    "push r14",
    "push r13",
    // Determine what execution mode we're in
    "mov r14, r15",
    "add r14, 0x8", // exec_mode is at offset 0x8 from base
    "mov r14, [r14]",
    "cmp r14d, 0x0",
    "je save_bochs",
    // We're in Lucid mode so save Lucid GPRs
    "save_lucid: ",
    "mov r14, r15",
    "add r14, 0x10", // lucid_regs is at offset 0x10 from base
    "jmp save_gprs",
    // We're in Bochs mode so save Bochs GPRs
    "save_bochs: ",
    "mov r14, r15",
    "add r14, 0x90", // bochs_regs is at offset 0x90 from base
    "jmp save_gprs",
    // Save the GPRS to memory
    "save_gprs: ",
    "mov [r14 + 0x0], rax",
    "mov [r14 + 0x8], rbx",
    "mov [r14 + 0x10], rcx",
    "mov [r14 + 0x18], rdx",
    "mov [r14 + 0x20], rsi",
    "mov [r14 + 0x28], rdi",
    "mov [r14 + 0x30], rbp",
    "mov r13, rsp",          // Get the current RSP value
    "add r13, 0x18",         // Recover original RSP after pushfq, push, push
    "mov [r14 + 0x38], r13", // Save original RSP value in bank
    "mov [r14 + 0x40], r8",
    "mov [r14 + 0x48], r9",
    "mov [r14 + 0x50], r10",
    "mov [r14 + 0x58], r11",
    "mov [r14 + 0x60], r12",
    "pop r13",               // Original R13 value now in R13
    "mov [r14 + 0x68], r13", // Save original R13 value
    "pop r13",               // Original R14 value now in R13
    "mov [r14 + 0x70], r13", // Save original R14 value to register bank
    "mov [r14 + 0x78], r15",
    // Set up the context function argument for the exit handler
    "mov rdi, r15",
    // Change over to the scratch stack for context switch stuff
    "mov rsp, [r15 + 0x110]",
    // We're ready to call a function now since we've saved all of our registers
    "call switch_handler",
    // Get original RSP back
    "mov rsp, [r14 + 0x38]",
    // To recover pointer to cpu flags
    "sub rsp, 0x8",
    // Restore the flags
    "popfq",
    // Restore the GPRS
    "mov rax, [r14 + 0x0]",
    "mov rbx, [r14 + 0x8]",
    "mov rcx, [r14 + 0x10]",
    "mov rdx, [r14 + 0x18]",
    "mov rsi, [r14 + 0x20]",
    "mov rdi, [r14 + 0x28]",
    "mov rbp, [r14 + 0x30]",
    "mov rsp, [r14 + 0x38]",
    "mov r8, [r14 + 0x40]",
    "mov r9, [r14 + 0x48]",
    "mov r10, [r14 + 0x50]",
    "mov r11, [r14 + 0x58]",
    "mov r12, [r14 + 0x60]",
    "mov r13, [r14 + 0x68]",
    "mov r15, [r14 + 0x78]", // Restore R15 before R14
    "mov r14, [r14 + 0x70]",
    // Return execution back to caller!
    "ret"
);

// Where we handle errors during context switching or syscalls, we just set
// an error value in the context and then switch execution back over to Lucid
pub fn fault_handler(contextp: *mut LucidContext, err: LucidErr) {
    // Plumb up the error
    let context = LucidContext::from_ptr_mut(contextp);
    context.err = Some(err);

    // Attempt to restore Lucid execution
    restore_lucid_execution(contextp);
}

// Restore Lucid's state from last saved on context-switch
fn restore_lucid_execution(contextp: *mut LucidContext) {
    // Set the mode to Lucid
    let context = LucidContext::from_ptr_mut(contextp);
    context.exec_mode = ExecMode::Lucid;

    // Get the Lucid register bank pointer
    let lucid_regsp = context.lucid_regs_ptr();

    // Restore extended state
    context.restore_xstate();

    // Move that pointer into R14 and restore our GPRs
    unsafe {
        asm!(
            "mov r14, {0}",
            "mov rax, [r14 + 0x0]",
            "mov rbx, [r14 + 0x8]",
            "mov rcx, [r14 + 0x10]",
            "mov rdx, [r14 + 0x18]",
            "mov rsi, [r14 + 0x20]",
            "mov rdi, [r14 + 0x28]",
            "mov rbp, [r14 + 0x30]",
            "mov rsp, [r14 + 0x38]",
            "mov r8, [r14 + 0x40]",
            "mov r9, [r14 + 0x48]",
            "mov r10, [r14 + 0x50]",
            "mov r11, [r14 + 0x58]",
            "mov r12, [r14 + 0x60]",
            "mov r13, [r14 + 0x68]",
            "mov r15, [r14 + 0x78]",
            "mov r14, [r14 + 0x70]",
            "sub rsp, 0x8",             // Recover saved CPU flags
            "popfq",
            "ret",
            in(reg) lucid_regsp,
        );
    }
}

// Restore Bochs' state from the snapshot
fn restore_bochs_execution(contextp: *mut LucidContext) {
    // Set the mode to Bochs
    let context = LucidContext::from_ptr_mut(contextp);
    context.exec_mode = ExecMode::Bochs;

    // Get the pointer to the snapshot regs
    let snap_regsp = context.snapshot_regs_ptr();

    // Restore the extended state
    context.restore_xstate();

    // Move that pointer into R14 and restore our GPRs
    unsafe {
        asm!(
            "mov r14, {0}",
            "mov rax, [r14 + 0x0]",
            "mov rbx, [r14 + 0x8]",
            "mov rcx, [r14 + 0x10]",
            "mov rdx, [r14 + 0x18]",
            "mov rsi, [r14 + 0x20]",
            "mov rdi, [r14 + 0x28]",
            "mov rbp, [r14 + 0x30]",
            "mov rsp, [r14 + 0x38]",
            "mov r8, [r14 + 0x40]",
            "mov r9, [r14 + 0x48]",
            "mov r10, [r14 + 0x50]",
            "mov r11, [r14 + 0x58]",
            "mov r12, [r14 + 0x60]",
            "mov r13, [r14 + 0x68]",
            "mov r15, [r14 + 0x78]",
            "mov r14, [r14 + 0x70]",
            "sub rsp, 0x8",             // Recover saved CPU flags
            "popfq",
            "ret",
            in(reg) snap_regsp,
        );
    }
}

// Called from main.rs
#[inline(never)]
pub fn start_bochs(context: &mut LucidContext) {
    // Set the execution mode and the reason why we're exiting the Lucid VM
    context.exec_mode = ExecMode::Lucid;
    context.exit_reason = VmExit::StartBochs;

    // Set up the calling convention and then start Bochs by context switching
    unsafe {
        asm!(
            "push r15", // Callee-saved register we have to preserve
            "mov r15, {0}", // Move context into R15
            "call qword ptr [r15]", // Call context_switch
            "pop r15",  // Restore callee-saved register
            in(reg) context as *mut LucidContext,
        );
    }
}

#[inline(never)]
pub fn resume_bochs(context: &mut LucidContext) {
    // Set the execution mode and the reason why we're exiting the Lucid VM
    context.exec_mode = ExecMode::Lucid;
    context.exit_reason = VmExit::ResumeBochs;

    // Set up the calling convention and then start Bochs by context switching
    unsafe {
        asm!(
            "push r15", // Callee-saved register we have to preserve
            "mov r15, {0}", // Move context into R15
            "call qword ptr [r15]", // Call context_switch
            "pop r15",  // Restore callee-saved register
            in(reg) context as *mut LucidContext,
        );
    }
}

// Called from main.rs
pub fn register_input(context: &mut LucidContext, signature: String) -> Result<(), LucidErr> {
    // If it starts with 0x, trim that off
    let sig = if signature.starts_with("0x") || signature.starts_with("0X") {
        &signature[2..]
    } else {
        &signature
    };

    // Make sure its the right length for 128 bit value
    if sig.len() != 32 {
        return Err(LucidErr::from(&format!(
            "Invalid signature string length {}, should be 32",
            sig.len()
        )));
    }

    // Try to convert the hex digits into bytes
    let mut sig_bytes: [u8; 16] = [0; 16];
    for i in 0..16 {
        let curr_byte = u8::from_str_radix(&sig[i * 2..i * 2 + 2], 16);
        if curr_byte.is_err() {
            return Err(LucidErr::from("Invalid non-hex value in signature"));
        }

        // Store byte
        sig_bytes[i] = curr_byte.unwrap();
    }

    // Search for the byte pattern in the MMU
    let candidates = context.mmu.search_memory(&sig_bytes);

    // Analyze search results
    let sig_addr = match candidates.len() {
        0 => return Err(LucidErr::from("Unable to find signature in memory")),
        1 => candidates[0],
        _ => return Err(LucidErr::from("Found input signature collision")),
    };

    // Input looks like this in harness:
    // - signature[16 bytes] [offset 0]
    // - input size [8 bytes] [offset 0x10]
    // - input [max input size] [offset 0x18]

    // Find location of input size
    context.input_size_addr = sig_addr + 0x10;

    // Find location of input buffer
    context.input_buf_addr = sig_addr + 0x18;

    Ok(())
}

// Helpers to update CPU time tracking in the Context->Stats
#[inline]
fn start_timer() -> std::time::Instant {
    std::time::Instant::now()
}

#[inline]
fn end_timer(time_bank: &mut std::time::Duration, start: std::time::Instant) {
    let elapsed = start.elapsed();
    *time_bank += elapsed;
}

// Reset Bochs to the snapshot state
pub fn reset_bochs(context: &mut LucidContext) -> Result<(), LucidErr> {
    restore_snapshot(context)?;
    Ok(())
}

// Places the required input in the Mutator's input buf
fn generate_input(context: &mut LucidContext) {
    // First try to get an entry in the Redqueen queue
    if let Some(input) = context.redqueen.test_queue.pop() {
        // Memcpy the input into the mutator's buffer
        context.mutator.memcpy_input(&input);

        // Update the fuzzing stage
        context.fuzzing_stage = FuzzingStage::Redqueen;
    }
    // If it was empty, have the mutator create a new input
    else {
        context.mutator.mutate_input(&context.corpus);

        // Update the fuzzing stage
        context.fuzzing_stage = FuzzingStage::Fuzzing;
    }
}

// Insert a fuzzcase into the target
#[inline]
pub fn insert_fuzzcase(context: &mut LucidContext) {
    // Update the size
    unsafe {
        let size_ptr = context.input_size_addr as *mut u64;
        core::ptr::write(size_ptr, context.mutator.input.len() as u64);
    }

    // Insert the fuzzing input
    unsafe {
        core::ptr::copy_nonoverlapping(
            context.mutator.input.as_ptr(),
            context.input_buf_addr as *mut u8,
            context.mutator.input.len(),
        );
    }
}

// Let Bochs resume execution from the snapshot and run the current fuzzcase,
// returns an error if Bochs hit something nasty like an unhandled syscall
pub fn run_fuzzcase(context: &mut LucidContext) -> Result<(), LucidErr> {
    // Context switch into Bochs to resume
    resume_bochs(context);

    // Check to see if there was an error during Bochs execution
    if context.err.is_some() {
        return Err(context.err.as_ref().unwrap().clone());
    }

    Ok(())
}

// Handle a crash that occurs
pub fn handle_crash(context: &mut LucidContext) {
    // Save crash
    context.corpus.save_crash(&context.mutator.input, "crash");

    // Update coverage
    context.coverage.update_coverage();

    // Update stats
    context.stats.crashes += 1;
    let edges = context.coverage.get_edge_count();
    context.stats.new_coverage(edges);
}

// Handle a timeout that occurs
pub fn handle_timeout(context: &mut LucidContext) {
    // Save timeout
    context.corpus.save_crash(&context.mutator.input, "timeout");

    // Update coverage
    context.coverage.update_coverage();

    // Update stats
    context.stats.timeouts += 1;
    let edges = context.coverage.get_edge_count();
    context.stats.new_coverage(edges);
}

// In the event that a fuzzing input finds new coverage, handle it here
pub fn handle_new_coverage(context: &mut LucidContext, old_edge_count: usize) -> usize {
    context.corpus.save_input(&context.mutator.input);
    let new_edge_count = context.coverage.get_edge_count();
    prompt!(
        "{} increased edge count {} -> {} (+{})",
        context.fuzzing_stage,
        old_edge_count,
        new_edge_count,
        new_edge_count - old_edge_count
    );

    // Update stats
    context.stats.new_coverage(new_edge_count);

    // Save this input into the Redqueen process queue
    context
        .redqueen
        .process_queue
        .push(context.mutator.input.clone());

    // Return new edge count to caller
    new_edge_count
}

// Time a function if we're in the fuzzing stage
macro_rules! time_func {
    ($context:expr, $stat_field:ident, $operation:expr) => {{
        if matches!($context.fuzzing_stage, FuzzingStage::Fuzzing) {
            let start = start_timer();
            let result = $operation;
            end_timer(&mut $context.stats.$stat_field, start);
            result
        } else if matches!($context.fuzzing_stage, FuzzingStage::Redqueen) {
            let start = start_timer();
            let result = $operation;
            end_timer(&mut $context.stats.$stat_field, start);
            result
        } else {
            $operation
        }
    }};
}

// Run one fuzzing iteration based on the current FuzzingStage
pub fn fuzz_one(context: &mut LucidContext) -> Result<FuzzingResult, LucidErr> {
    // Track fuzzing result
    let mut fuzzing_result = FuzzingResult::None;

    // Restore Bochs
    time_func!(context, batch_reset, reset_bochs(context))?;

    // Insert the fuzzcase into the target
    insert_fuzzcase(context);

    // Run the fuzzcase through
    time_func!(context, batch_target, run_fuzzcase(context))?;

    // Check for crash
    if context.crash == 1 {
        fuzzing_result = FuzzingResult::Crash;
        context.crash = 0;
    }
    // Check for timeout
    else if context.timeout == 1 {
        fuzzing_result = FuzzingResult::Timeout;
        context.timeout = 0;
    }
    // Check for coverage increase
    else if time_func!(context, batch_coverage, context.coverage.update_coverage()) {
        fuzzing_result = FuzzingResult::NewCoverage;
    }

    // Return the fuzzing result to the caller for further action
    Ok(fuzzing_result)
}

// Dry-run the seeds provided for the campaign, keep in mind that seeds may
// cause crashes or timeouts, we handle both of those possibilities
pub fn dry_run(context: &mut LucidContext) -> Result<(), LucidErr> {
    // Set the context fuzzing stage to dry run
    context.fuzzing_stage = FuzzingStage::DryRun;

    // For the number of inputs in the corpus, fuzz one
    for i in 0..context.corpus.num_inputs() {
        // Place the seed input in the mutator buf
        context
            .mutator
            .memcpy_input(context.corpus.get_input(i).unwrap());

        // Run the input through
        let result = fuzz_one(context);

        // Match on the result
        match result {
            Ok(FuzzingResult::Crash) => {
                prompt_warn!("Dry-run input caused crash!");
                handle_crash(context);
            }
            Ok(FuzzingResult::Timeout) => {
                prompt_warn!("Dry-run input caused timeout!");
                handle_timeout(context);
            }
            Err(e) => return Err(e),
            _ => (), // We don't care about new coverage or no result here
        }
    }

    Ok(())
}

// Try to grab an input for Redqueen processing and perform a Redqueen pass
fn try_redqueen(context: &mut LucidContext) -> Result<bool, LucidErr> {
    // If the process queue is empty, we're done here
    if context.redqueen.process_queue.is_empty() {
        return Ok(false);
    }

    // Get the input
    let input = context.redqueen.process_queue.pop().unwrap();

    // Make sure it's set in the mutator
    context.mutator.memcpy_input(&input);

    // Send the input off for Redqueen processing
    time_func!(context, batch_redqueen, redqueen_pass(context))?;

    Ok(true)
}

pub fn fuzz_loop(context: &mut LucidContext) -> Result<(), LucidErr> {
    // Quick sleep
    std::thread::sleep(std::time::Duration::from_secs(1));

    // Reset screen
    println!("\x1B[2J\x1B[1;1H");

    // Start time-keeping
    context.stats.start_session(context.coverage.curr_map.len());

    // Mark that we're fuzzing now
    context.fuzzing = true;
    context.fuzzing_stage = FuzzingStage::Fuzzing;

    // Keep track of old edge count
    let mut old_edge_count = context.coverage.get_edge_count();

    loop {
        // Try to clear out the Redqueen process queue first
        if try_redqueen(context)? {
            continue;
        }

        // Load a new input into the fuzzer
        time_func!(context, batch_mutator, generate_input(context));

        // Run the input through
        let fuzzing_result = match fuzz_one(context) {
            Ok(result) => result,
            Err(e) => {
                return Err(e);
            }
        };

        // Act on result
        match fuzzing_result {
            FuzzingResult::Crash => {
                handle_crash(context);
            }
            FuzzingResult::Timeout => {
                handle_timeout(context);
            }
            FuzzingResult::NewCoverage => {
                old_edge_count = handle_new_coverage(context, old_edge_count);
            }
            _ => (),
        }

        // Update stats
        context.stats.update();

        // Check stats
        if context.stats.report_ready() {
            context.stats.report();
        }
    }
}
