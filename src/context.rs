/// This file contains the logic necessary to perform context-switching between
/// Lucid and Bochs
///
/// The calling convention we use for context switching:
/// r15 -- Pointer to a LucidContext

use std::fmt;
use std::arch::{global_asm, asm};
use core::arch::x86_64::{_xgetbv, _xsave64, _fxsave64, _xrstor64, _fxrstor64};

use crate::err::LucidErr;
use crate::syscall::lucid_syscall;
use crate::mmu::Mmu;
use crate::files::FileTable;
use crate::fault;

// Duh
const PAGE_SIZE: usize = 0x1000;

// Magic number member of the LucidContext, chosen by ChatGPT 
pub const CTX_MAGIC: usize = 0x74DFF25D576D6F4D;

// In the context-switching code here, we can't really continue if we encounter
// errors at this point, so we're using this error type of `Fault` to somewhat
// differentiate errors in the project and reserving this type to mean that 
// something went awry in the "context-switching" like code. So far, we don't 
// recover from these
#[repr(i32)]
#[derive(Clone, Copy, Debug)]
pub enum Fault {
    Success,
    BadExitReason,
    BadSaveInstruction,
    BadSaveArea,
    NullContext,
    BadMagic,
    BadXcr0,
    BadLucidExit,
    BadBochsExit,
    BadExecMode,
    Syscall,
    SyscallMagic,
    EarlyBochsExit,
    InvalidBrk,
    InvalidMmap,
    NullPath,
    InvalidPathStr,
    NoFile,
}

// So we can plumb these up into LucidErrs if we need to
impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let description = match *self {
            Fault::Success => "No fault",
            Fault::BadExitReason => "Invalid exit reason",
            Fault::BadSaveInstruction => "Invalid save instruction",
            Fault::BadSaveArea => "Invalid save area",
            Fault::NullContext => "Context was NULL",
            Fault::BadMagic => "Invalid magic value",
            Fault::BadXcr0 => "Invalid XCR0 value",
            Fault::BadLucidExit => "Invalid Lucid exit reason",
            Fault::BadBochsExit => "Invalid Bochs exit reason",
            Fault::BadExecMode => "Invalid execution mode",
            Fault::Syscall => "Fault during syscall",
            Fault::SyscallMagic => "Invalid magic value in syscall",
            Fault::EarlyBochsExit => "Bochs exited early",
            Fault::InvalidBrk => "Invalid `brk` request",
            Fault::InvalidMmap => "Invalid `mmap` request",
            Fault::NullPath => "Open path was NULL",
            Fault::InvalidPathStr => "Open path contained invalid characters",
            Fault::NoFile => "File I/O on non-existent file",

        };
        write!(f, "{}", description)
    }
}

// This represents the reason why a VM has exited execution and is now trying
// to context-switch for event handling
#[derive(Clone, Copy, Debug)]
pub enum VmExit {
    NoExit = 0,
    StartBochs = 1,
}

// We get passed an i32, have to go through this to get a Rust enum
impl TryFrom<i32> for VmExit {
    // Dummy error
    type Error = ();

    // Return value or error
    fn try_from(val: i32) -> Result<Self, Self::Error> {
        match val {
            1 => Ok(VmExit::StartBochs),
            _ => Err(()),
        }
    }
}

// The kind of extended state saving instruction we need to use based on our 
// processor
#[repr(i32)]
#[derive(Debug, Clone, Copy)]
pub enum SaveInst {
    NoSave   = 0,
    XSave64  = 1,
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
    padding0: [u8; 8], // char c
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
    pub rax:    usize,
    rbx:        usize,
    rcx:        usize,
    pub rdx:    usize,
    pub rsi:    usize,
    pub rdi:    usize,
    rbp:        usize,
    rsp:        usize,
    pub r8:     usize,
    pub r9:     usize,
    pub r10:    usize,
    r11:        usize,
    r12:        usize,
    r13:        usize,
    r14:        usize,
    r15:        usize,
}

// Execution context that is passed between Lucid and Bochs that tracks
// all of the mutable state information we need to do context-switching
#[repr(C)]
#[derive(Clone)]
pub struct LucidContext {
    pub context_switch: usize,  // Address of context_switch()
    mode: ExecMode,             // Our current mode of execution
    lucid_regs: RegisterBank,   // Holds Lucid register state for GPRs
    bochs_regs: RegisterBank,   // Holds Bochs register state for GRPs
    pub fault: Fault,           // Current fault code if there is one
    exit_reason: VmExit,        // Why we're context switching
    lucid_syscall: usize,       // Address of lucid_syscall()
    save_inst: SaveInst,        // Type of save instruction we use for exstate
    save_size: usize,           // Size of the save area
    lucid_save_area: usize,     // Pointer to the save area for Lucid
    bochs_save_area: usize,     // Pointer to the save area for Bochs
    xcr0: usize,                // The xcr0 value when we initialize
    bochs_entry: usize,         // Entry point for Bochs ELF
    bochs_rsp: usize,           // Stack that Bochs uses
    pub tls: Tls,               // Bochs' TLS instance
    pub magic: usize,           // Magic value for debugging purposes
    pub fs_reg: usize,          // The %fs reg value that we're faking

    /* Opaque Members start here, not defined on C side */
    pub mmu: Mmu,               // Bochs' memory manager
    pub clock_time: usize,      // Nanoseconds
    pub files: FileTable,       // Bochs' files
}

// Functions taking a pointer as an arg should have been NULL-checked by caller
impl LucidContext {
    pub fn get_magic(context: *const LucidContext) -> usize {
        unsafe { (*context).magic }
    }

    pub fn get_exit_reason(context: *const LucidContext) ->
        Result<VmExit, ()> {
        // Raw deref to get an i32 value
        let exit_reason = unsafe { (*context).exit_reason as i32 };

        // Try to cast the i32 to a VmExit enum
        let Ok(exit_reason) = VmExit::try_from(exit_reason) else {
            return Err(());
        };

        // Return reason
        Ok(exit_reason)
    }

    pub fn get_save_inst(context: *const LucidContext) ->
        Result<SaveInst, ()> {
        // Raw deref to get an i32 value
        let save_inst = unsafe { (*context).save_inst as i32 };
        
        // Try to cast the i32 to a SaveInst enum
        let Ok(save_inst) = SaveInst::try_from(save_inst) else {
            return Err(());
        };

        // Return save instruction
        Ok(save_inst)
    }

    pub fn is_lucid_mode(context: *const LucidContext) ->
        bool {
        // Raw deref to get an i32 value
        let mode = unsafe { (*context).mode as i32 };
        
        // Try to cast the i32 to a ExecMode enum
        let Ok(mode) = ExecMode::try_from(mode) else {
            return false;
        };

        // Return true or false
        matches!(mode, ExecMode::Lucid)
    }

    pub fn is_bochs_mode(context: *const LucidContext) ->
        bool {
        // Raw deref to get an i32 value
        let mode = unsafe { (*context).mode as i32 };
        
        // Try to cast the i32 to a ExecMode enum
        let Ok(mode) = ExecMode::try_from(mode) else {
            return false;
        };

        // Return true or false
        matches!(mode, ExecMode::Bochs)
    }

    #[allow(unreachable_patterns)]
    pub fn get_save_area(context: *const LucidContext)
        -> usize {
        let context = unsafe { &*context };

        match context.mode {
            ExecMode::Bochs => context.bochs_save_area,
            ExecMode::Lucid => context.lucid_save_area,
            _ => 0,
        }
    }

    pub fn _get_lucid_regs(context: *mut LucidContext) ->
        &'static mut RegisterBank {
        unsafe { &mut (*context).lucid_regs }
    }

    pub fn _get_bochs_regs(context: *mut LucidContext) ->
        &'static mut RegisterBank {
        unsafe { &mut (*context).bochs_regs }
    }

    // Only ever called from main.rs, so return LucidErr at that level not Fault
    pub fn new(entry: usize, rsp: usize) -> Result<Self, LucidErr> {
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

        // If we have a save_size, we need to capture XCR0's value
        let xcr0 = if save_size != 0 {
            (unsafe { _xgetbv(0) }) as usize
        } else {
            0_usize
        };

        // If we have to save, let's map some memory to save the extended
        // state for the fuzzer and Bochs
        let (lucid_save_area, bochs_save_area) = match save_inst {
            SaveInst::NoSave => (0, 0),
            _ => map_save_areas(save_size)?,
        };

        // Create default (empty) register banks for the GPRs
        let lucid_regs = RegisterBank::default();
        let bochs_regs = RegisterBank::default();

        // We can only initialize an execution context from Lucid, so this is
        // self-explanatory
        let mode = ExecMode::Lucid;

        // We don't start with an exit reason, that needs to be set by caller
        let exit_reason = VmExit::NoExit;

        // We don't start with a fault obviously
        let fault = Fault::Success;

        // Create a new Tls
        let tls = Tls::new();

        // Create an MMU
        let mmu = Mmu::new()?;

        // Create a new FileTable
        let files = FileTable::new();

        // Build and return the execution context so we can fuzz!
        Ok(LucidContext {
            context_switch: context_switch as usize,
            mode,
            fault,
            exit_reason,
            lucid_syscall: lucid_syscall as usize,
            save_inst,
            save_size,
            lucid_save_area,
            bochs_save_area,
            lucid_regs,
            bochs_regs,
            xcr0,
            bochs_entry: entry,
            bochs_rsp: rsp,
            tls,
            magic: CTX_MAGIC,
            fs_reg: 0,
            mmu,
            clock_time: 0,
            files,
        })
    }
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
// we actually surround the save area with guard pages with no perms just to 
// fail explicitly if anything weird happens. We return two page addresses
// Guard page -- No perms
// Save area -- RW <-- Returned
// Guard page -- No perms
// Save area -- RW <-- Returned
// Guard page -- No perms
fn map_save_areas(size: usize) -> Result<(usize, usize), LucidErr> {
    assert!(size % PAGE_SIZE == 0);

    // Track the mapping addrs
    let mut ret_addrs = (0, 0);

    // We need 3 total guard pages
    let page_size = PAGE_SIZE * 3;

    // We have two separate save areas, so we multiply by 2
    let doubled_size = size.checked_mul(2)
        .ok_or(LucidErr::from("Integer Overflow"))?;

    // The total mapping size we need is the guard pages + the save areas
    let map_size = page_size.checked_add(doubled_size)
        .ok_or(LucidErr::from("Integer Overflow"))?;

    // Cast to libc
    let map_size = map_size as libc::size_t;

    // Set the protection to none for now
    let prot = libc::PROT_NONE;

    // Anonymous mem
    let flags = libc::MAP_ANONYMOUS | libc::MAP_PRIVATE;

    // No file and no offset
    let fd = -1 as libc::c_int;
    let offset = 0 as libc::off_t;

    // Map the memory
    let result = unsafe {
        libc::mmap(
            std::ptr::null_mut::<libc::c_void>(),
            map_size,
            prot,
            flags,
            fd,
            offset
        )
    };

    if result == libc::MAP_FAILED {
        return Err(LucidErr::from("Failed `mmap` memory for save area"));
    }

    // Now we need to calculate where to add permissions
    let mut curr_addr: usize = result as usize;

    // Increase by the guard page
    curr_addr += PAGE_SIZE;

    // Make a copy of this address for return
    ret_addrs.0 = curr_addr;

    // Now for size, we need to change the perms of this range
    let mut mprotect = unsafe {
        libc::mprotect(
            curr_addr as *mut libc::c_void,
            size as libc::size_t,
            libc::PROT_READ | libc::PROT_WRITE
        )
    };

    if mprotect == -1 {
        return Err(LucidErr::from("Failed to `mprotect` save area"));
    }

    // Increment the pointer now to cover the changed range
    curr_addr += size;

    // Increment the pointer over the next guard page
    curr_addr += PAGE_SIZE;

    // Make a copy again
    ret_addrs.1 = curr_addr;

    // Call mprotect a final time to change the perms of the 2nd save area
    mprotect = unsafe {
        libc::mprotect(
            curr_addr as *mut libc::c_void,
            size as libc::size_t,
            libc::PROT_READ | libc::PROT_WRITE
        )
    };

    if mprotect == -1 {
        return Err(LucidErr::from("Failed to `mprotect` save area"));
    }

    // We made it, return the mapping addresses for the save areas
    Ok(ret_addrs)
}

// Standalone function to literally jump to Bochs entry and provide the stack
// address to Bochs
fn jump_to_bochs(context: *mut LucidContext) {
    // RDX: we have to clear this register as the ABI specifies that exit
    // hooks are set when rdx is non-null at program start
    //
    // RAX: arbitrarily used as a jump target to the program entry
    //
    // RSP: Rust does not allow you to use 'rsp' explicitly with in(), so we
    // have to manually set it with a `mov`
    //
    // R15: holds a pointer to the execution context, if this value is non-
    // null, then Bochs learns at start time that it is running under Lucid
    //
    // We don't really care about execution order as long as we specify clobbers
    // with out/lateout, that way the compiler doesn't allocate a register we 
    // then immediately clobber
    unsafe {
        asm!(
            "xor rdx, rdx",
            "mov rsp, {0}",
            "mov r15, {1}",
            "jmp rax",
            in(reg) (*context).bochs_rsp,
            in(reg) context,
            in("rax") (*context).bochs_entry,
            lateout("rax") _,   // Clobber (inout so no conflict with in)
            out("rdx") _,       // Clobber
            out("r15") _,       // Clobber
        );
    }
}

// This is where the actual logic is for handling the Bochs exit, we have to 
// use no_mangle here so that we can call it from the assembly blob. We need
// to see why we've exited and dispatch to the appropriate function
#[no_mangle]
fn switch_handler(context: *mut LucidContext) {
    // We have to make sure this bad boy isn't NULL 
    if context.is_null() {
        fault!(context, Fault::NullContext);
    }

    // Ensure that we have our magic value intact, if this is wrong, then we 
    // are in some kind of really bad state and just need to die
    let magic = LucidContext::get_magic(context);
    if magic != CTX_MAGIC {
        fault!(context, Fault::BadMagic);
    }

    // Before we do anything else, save the extended state
    let Ok(save_inst) = LucidContext::get_save_inst(context) else {
        fault!(context, Fault::BadSaveInstruction);
    };

    // Get the save area
    let save_area = LucidContext::get_save_area(context);
    if save_area == 0 || save_area % 64 != 0 {
        fault!(context, Fault::BadSaveArea);
    }

    // Determine save logic
    match save_inst {
        SaveInst::XSave64 => {
            // Retrieve XCR0 value, this will serve as our save mask
            let xcr0 = unsafe { _xgetbv(0) };

            // Make sure this matches the original xcr0
            if xcr0 !=  unsafe { (*context).xcr0 } as u64 {
                fault!(context, Fault::BadXcr0);
            }

            // Call xsave to save the extended state to Bochs save area
            unsafe { _xsave64(save_area as *mut u8, xcr0); }             
        },
        SaveInst::FxSave64 => {
            // Call fxsave to save the extended state to Bochs save area
            unsafe { _fxsave64(save_area as *mut u8); }
        },
        _ => (), // NoSave
    }

    // Try to get the VmExit reason 
    let Ok(exit_reason) = LucidContext::get_exit_reason(context) else {
        fault!(context, Fault::BadExitReason);
    };
    
    // Handle Lucid context switches here
    if LucidContext::is_lucid_mode(context) {
        match exit_reason {
            // Dispatch to Bochs entry point
            VmExit::StartBochs => {
                jump_to_bochs(context);
            },
            _ => {
                fault!(context, Fault::BadLucidExit);
            }
        }
    }

    // Handle Bochs context switches here
    else if LucidContext::is_bochs_mode(context) {
        fault!(context, Fault::BadBochsExit);
    }

    // Should never reach this, right?
    else {
        fault!(context, Fault::BadExecMode);
    }

    // Restore extended state, determine restore logic
    match save_inst {
        SaveInst::XSave64 => {
            // Retrieve XCR0 value, this will serve as our save mask
            let xcr0 = unsafe { _xgetbv(0) };

            // Call xrstor to restore the extended state from Bochs save area
            unsafe { _xrstor64(save_area as *const u8, xcr0); }             
        },
        SaveInst::FxSave64 => {
            // Call fxrstor to restore the extended state from Bochs save area
            unsafe { _fxrstor64(save_area as *const u8); }
        },
        _ => (), // NoSaveS
    }
}

// This is our context_switch function, this stub is meant to save as much state
// as necessary before we can start calling regular Rust functions, right now it
// saves the CPU flags and the GPRs before calling int `switch_handler`.
extern "C" { fn context_switch(); }
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
    "add r14, 0x8",     // mode is at offset 0x8 from base
    "mov r14, [r14]",
    "cmp r14d, 0x0",
    "je save_bochs",

    // We're in Lucid mode so save Lucid GPRs
    "save_lucid: ",
    "mov r14, r15",
    "add r14, 0x10",    // lucid_regs is at offset 0x10 from base
    "jmp save_gprs",             

    // We're in Bochs mode so save Bochs GPRs
    "save_bochs: ",
    "mov r14, r15",
    "add r14, 0x90",    // bochs_regs is at offset 0x90 from base
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
    "mov r13, rsp",             // Get the current RSP value
    "add r13, 0x18",            // Recover original RSP after pushfq, push, push
    "mov [r14 + 0x38], r13",    // Save original RSP value in bank
    "mov [r14 + 0x40], r8",
    "mov [r14 + 0x48], r9",
    "mov [r14 + 0x50], r10",
    "mov [r14 + 0x58], r11",
    "mov [r14 + 0x60], r12",
    "pop r13",                  // Original R13 value now in R13
    "mov [r14 + 0x68], r13",    // Save original R13 value
    "pop r13",                  // Original R14 value now in R13
    "mov [r14 + 0x70], r13",    // Save original R14 value to register bank
    "mov [r14 + 0x78], r15",

    // Set up the context function argument for the exit handler
    "mov rdi, r15",

    // We're ready to call a function now since we've saved all of our registers
    // but we need to make sure RSP is 16-byte aligned before the call
    "test rsp, 0xF",
    "jz aligned",
    "sub rsp, 0x8",

    "aligned: ",
    "call switch_handler",
    
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
    "mov r15, [r14 + 0x78]",    // Restore R15 before R14
    "mov r14, [r14 + 0x70]",

    // Return execution back to caller!
    "ret"
);

// Where we handle faults that may occur when context-switching from Bochs. We
// just want to make the fault visible to Lucid so we set it in the context,
// then we try to restore Lucid execution from its last-known good state
pub fn fault_handler(contextp: *mut LucidContext, fault: Fault) {
    let context = unsafe { &mut *contextp };
    match fault {
        Fault::Success => context.fault = Fault::Success,
        Fault::BadExitReason => context.fault = Fault::BadExitReason,
        Fault::BadSaveInstruction => context.fault = Fault::BadSaveInstruction,
        Fault::BadSaveArea => context.fault = Fault::BadSaveArea,
        Fault::NullContext => context.fault = Fault::NullContext,
        Fault::BadMagic => context.fault = Fault::BadMagic,
        Fault::BadXcr0 => context.fault = Fault::BadXcr0,
        Fault::BadLucidExit => context.fault = Fault::BadLucidExit,
        Fault::BadBochsExit => context.fault = Fault::BadBochsExit,
        Fault::BadExecMode => context.fault = Fault::BadExecMode,
        Fault::Syscall => context.fault = Fault::Syscall,
        Fault::SyscallMagic => context.fault = Fault::SyscallMagic,
        Fault::EarlyBochsExit => context.fault = Fault::EarlyBochsExit,
        Fault::InvalidBrk => context.fault = Fault::InvalidBrk,
        Fault::InvalidMmap => context.fault = Fault::InvalidMmap,
        Fault::NullPath => context.fault = Fault::NullPath,
        Fault::InvalidPathStr => context.fault = Fault::InvalidPathStr,
        Fault::NoFile => context.fault = Fault::NoFile,
    }

    // Attempt to restore Lucid execution
    restore_lucid_execution(contextp);
}

// We use this function to restore Lucid execution to its last known good state
// This is just really trying to plumb up a fault to a level that is capable of
// discerning what action to take. Right now, we probably just call it fatal. 
// We don't really deal with double-faults, it doesn't make much sense at the
// moment when a single-fault will likely be fatal already. Maybe later?
fn restore_lucid_execution(contextp: *mut LucidContext) {
    let context = unsafe { &mut *contextp };
    
    // Fault should be set, but change the execution mode now since we're
    // jumping back to Lucid
    context.mode = ExecMode::Lucid;

    // Restore extended state
    let save_area = context.lucid_save_area;
    let save_inst = context.save_inst;
    match save_inst {
        SaveInst::XSave64 => {
            // Retrieve XCR0 value, this will serve as our save mask
            let xcr0 = unsafe { _xgetbv(0) };

            // Call xrstor to restore the extended state from Bochs save area
            unsafe { _xrstor64(save_area as *const u8, xcr0); }             
        },
        SaveInst::FxSave64 => {
            // Call fxrstor to restore the extended state from Bochs save area
            unsafe { _fxrstor64(save_area as *const u8); }
        },
        _ => (), // NoSave
    }

    // Next, we need to restore our GPRs. This is kind of different order than
    // returning from a successful context switch since normally we'd still be
    // using our own stack; however right now, we still have Bochs' stack, so
    // we need to recover our own Lucid stack which is saved as RSP in our 
    // register bank
    let lucid_regsp = &context.lucid_regs as *const _;

    // Move that pointer into R14 and restore our GPRs. After that we have the
    // RSP value that we saved when we called into context_switch, this RSP was
    // then subtracted from by 0x8 for the pushfq operation that comes right
    // after. So in order to recover our CPU flags, we need to manually sub
    // 0x8 from the stack pointer. Pop the CPU flags back into place, and then 
    // return to the last known good Lucid state
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
            "sub rsp, 0x8",
            "popfq",
            "ret",
            in(reg) lucid_regsp,
        );
    }
}

// Called from main.rs
#[inline(never)]
pub fn start_bochs(context: &mut LucidContext) {
    // Set the execution mode and the reason why we're exiting the Lucid VM
    context.mode = ExecMode::Lucid;
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