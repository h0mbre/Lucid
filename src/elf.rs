/// This file contains all of the logic necessary for parsing a Bochs ELF and
/// creating consumable data structures that allow Bochs to be loaded in memory

use crate::err::LucidErr;

// Size of a 64-bit ELF headers
pub const ELF_HDR_SIZE: usize = 0x40;
pub const PRG_HDR_SIZE: usize = 0x38;
const SEC_HDR_SIZE: usize = 0x40;

// Our representation of an ELF
#[derive(Debug)]
pub struct Elf {
    pub elf_header: ElfHeader,
    pub program_headers: Vec<ProgramHeader>,
    pub section_headers: Vec<SectionHeader>,
    pub data: Vec<u8>,
}

// Constituent parts of the Elf
#[derive(Debug)]
pub struct ElfHeader {
    pub entry: u64,
    pub phoff: u64,
    pub shoff: u64,
    pub phentsize: u16,
    pub phnum: u16,
    pub shentsize: u16,
    pub shnum: u16,
    pub shrstrndx: u16,
}

#[derive(Debug)]
pub struct ProgramHeader {
    pub typ: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub paddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64, 
}

impl ProgramHeader {
    pub fn is_load(&self) -> bool {
        self.typ == 1
    }
}

#[derive(Debug)]
pub struct SectionHeader {
    pub name: u32,
    pub typ: u32,
    pub flags: u64,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub addralign: u64,
    pub entsize: u64,
}

// Attempt to parse an ELF header, pretty loose parsing here just meant to make
// sure that our Bochs ELF is sane, not meant to the be the world's best ELF 
// parser
fn parse_elf_header(data: &[u8]) -> Result<ElfHeader, LucidErr> {
    // Stack buffer we use to parse u64s out of the header with
    let mut arr64 = [0u8; 8];

    // Stack buffer we use to parse u16s out of the header with
    let mut arr16 = [0u8; 2];

    // Make sure we have enough bytes to parse a header
    if data.len() < ELF_HDR_SIZE {
        return Err(LucidErr::from(&format!(
            "Bad Elf Header Size: {}", data.len())));
    }

    // Check the byte signature
    if data[0x0..0x4] != [0x7F, 0x45, 0x4C, 0x46] {
        return Err(LucidErr::from("Bad Elf Header Sig"));
    }

    // Make sure we're dealing with a 64-bit ELF, 1 == 32-bit, 2 == 64-bit
    if data[0x4] != 2 {
        return Err(LucidErr::from("Bad Elf Header Not 64-bit"));
    }

    // Check the endianness of the ELF, 1 == Litte, 2 == Big
    if data[0x5] != 1 {
        return Err(LucidErr::from(
            "Bad Elf Header Not Little-Endian"));
    }

    // Version should be 1
    if data[0x6] != 1 {
        return Err(LucidErr::from("Bad Elf Header Bad Version"));
    }

    // Operating system ABI
    // 3: Linux
    // 0: Unix System V
    if data[0x7] != 3 && data[0x7] != 0 {
        return Err(LucidErr::from("Bad Elf Header Bad Operating System ABI"));
    }

    // Offset 8 - 16 should be meaningless/padding, skip those, check type,
    // should be 0x3 for ET_DYN (Shared object), because we are compiling with
    // --static-pie, `file` actually says that our executable is a shared object
    if data[0x10] != 0x3 {
        return Err(LucidErr::from(&format!(
            "Bad Elf Header Unrecognized Type: 0x{:x}", data[16])));
    }

    // Skip machine specification and version, we already parsed version, we 
    // don't care about the machine, we definitely care about the entry point
    arr64.copy_from_slice(&data[0x18..0x20]);
    let entry = u64::from_le_bytes(arr64);

    // Get the program header offset, this should be 0x40 in our case, just bail
    // if it is not, that is weird
    arr64.copy_from_slice(&data[0x20..0x28]);
    let phoff = u64::from_le_bytes(arr64);
    if phoff != ELF_HDR_SIZE as u64 {
        return Err(LucidErr::from(
            &format!("Bad Elf Header Bad phoff: {}", phoff)));
    }

    // Get the section header offset
    arr64.copy_from_slice(&data[0x28..0x30]);
    let shoff = u64::from_le_bytes(arr64);

    // Skip flags, check to make sure that the size of the ELF header is 0x40
    arr16.copy_from_slice(&data[0x34..0x36]);
    if u16::from_le_bytes(arr16) as usize != ELF_HDR_SIZE {
        return Err(LucidErr::from("Bad Elf Header Bad ehsize"));
    }

    // Get the size of a program header entry in the program table
    arr16.copy_from_slice(&data[0x36..0x38]);
    let phentsize = u16::from_le_bytes(arr16);

    // Get the number of program header entries
    arr16.copy_from_slice(&data[0x38..0x3A]);
    let phnum = u16::from_le_bytes(arr16);

    // Get the size of a section header entry in the section table
    arr16.copy_from_slice(&data[0x3A..0x3C]);
    let shentsize = u16::from_le_bytes(arr16);

    // Get the number of section entries
    arr16.copy_from_slice(&data[0x3C..0x3E]);
    let shnum = u16::from_le_bytes(arr16);

    // Get the section header table entry index for the section names
    arr16.copy_from_slice(&data[0x3E..0x40]);
    let shrstrndx = u16::from_le_bytes(arr16); 
        
    Ok(ElfHeader {
        entry,
        phoff,
        shoff,
        phentsize,
        phnum,
        shentsize,
        shnum,
        shrstrndx,
    })
}

// Try to parse the program headers 
fn parse_program_header(elf_header: &ElfHeader, data: &[u8])
    -> Result <Vec<ProgramHeader>, LucidErr> {
    // Stack buffer for parsing u64 values 
    let mut arr64 = [0u8; 8];

    // Stack buffer for parsing u32 values
    let mut arr32 = [0u8; 4];

    // First thing we need to do is make sure we have enough bytes to continue,
    // subtract the Elf header size from our slice
    let remaining = data.len() - ELF_HDR_SIZE;

    // Safely calculate how large the program header table is supposed to be
    let Some(table_size) = elf_header.phentsize.checked_mul(elf_header.phnum)
        else {
        return Err(LucidErr::from("Bad Program Header Size Overflow"));
    };

    // Check to see if we have enough data left
    if table_size as usize > remaining {
        return Err(LucidErr::from("Bad Program Header Insufficient Data"));
    }

    // Store fully formed ProgramHeader structs here
    let mut program_headers: Vec<ProgramHeader> = Vec::new();

    // Set the starting offset to where we left off parsing, we already know we
    // are safe to do this kind of looping and indexing because we've validated
    // the length of the data
    let mut off = ELF_HDR_SIZE;

    // Loop over each entry and create a ProgramHeader, but we have some things
    // to check:
    // 1. Make sure there is at least one loadable header!
    // 2. The vaddr of one of the loadable headers needs to be 0x0 
    let mut loadable = false;
    let mut vaddr_zero = false;
    for _ in 0..elf_header.phnum {
        // Create a copy of the data to work with
        let pheader_data = &data[off..off + PRG_HDR_SIZE];

        // Get the p_type
        arr32.copy_from_slice(&pheader_data[0x0..0x4]);
        let typ = u32::from_le_bytes(arr32);

        // Validate the p_type
        match typ {
            0..=7 => {
                if typ == 1 { loadable = true; };
            },
            0x60000000 => (),
            0x6FFFFFFF => (),
            0x70000000 => (),
            0x7FFFFFFF => (),
            0x6474E553 => (),
            0x6474E551 => (),
            0x6474E552 => (),
            0x6474E550 => (),
            _ => {
                return Err(LucidErr::from(
                    &format!("Bad Program Header p_type: 0x{:X}", typ)));
            }
        }

        // Get the p_flags
        arr32.copy_from_slice(&pheader_data[0x4..0x8]);
        let flags = u32::from_le_bytes(arr32);

        // Get the p_offset
        arr64.copy_from_slice(&pheader_data[0x8..0x10]);
        let offset = u64::from_le_bytes(arr64);

        // Get the p_vaddr
        arr64.copy_from_slice(&pheader_data[0x10..0x18]);
        let vaddr = u64::from_le_bytes(arr64);

        // Check to see if the address is 0x0
        if vaddr == 0x0 {
            vaddr_zero = true;
        }

        // Get the p_paddr
        arr64.copy_from_slice(&pheader_data[0x18..0x20]);
        let paddr = u64::from_le_bytes(arr64);

        // Get the p_filesz
        arr64.copy_from_slice(&pheader_data[0x20..0x28]);
        let filesz = u64::from_le_bytes(arr64);

        // Get the p_memsz
        arr64.copy_from_slice(&pheader_data[0x28..0x30]);
        let memsz = u64::from_le_bytes(arr64);

        // Make sure that filesz is always less than memsz if it's loadable, 
        // because we assume this later when we memcpy
        if loadable && filesz > memsz {
            return Err(LucidErr::from("Bad Program Header filesz > memsz"));
        }

        // Get the p_align
        arr64.copy_from_slice(&pheader_data[0x30..0x38]);
        let align = u64::from_le_bytes(arr64);

        // Create the finished struct
        let pheader = ProgramHeader {
            typ,
            flags,
            offset,
            vaddr,
            paddr,
            filesz,
            memsz,
            align,
        };

        // Save the result
        program_headers.push(pheader);

        // Update the offset, size of 64-bit program header
        off += PRG_HDR_SIZE;
    }

    // If we didn't find a loadable program header, bail
    if !loadable { return Err(LucidErr::from(
        "Bad Program Headers Nothing Loadable"));
    }

    // If we didn't find a program header with a vaddr of 0x0, bail
    if !vaddr_zero { return Err(LucidErr::from(
        "Bad Program Headers No Zero Vaddr"));
    }

    Ok(program_headers)
}

// Try to parse the section headers
fn parse_section_header(elf_header: &ElfHeader, data: &[u8])
    -> Result<Vec<SectionHeader>, LucidErr> {
    // Stack buffer for parsing u64 values
    let mut arr64 = [0u8; 8];

    // Stack buffer for parsing u32 values
    let mut arr32 = [0u8; 4];

    // Calculate how much size we've already consumed thus far, we don't need
    // to worry about arithmetic overflows here because this much has already
    // been validated
    let consumed = ELF_HDR_SIZE + PRG_HDR_SIZE * elf_header.phnum as usize;

    // Calculate how much we have remaining
    let remaining = data.len() - consumed;

    // Safely calculate how large the section header table is supposed to be
    let Some(table_size) = elf_header.shentsize.checked_mul(elf_header.shnum)
        else {
        return Err(LucidErr::from("Bad Section Header Size Overflow"));
    };

    // Check to see if we have enough data left
    if table_size as usize > remaining {
        return Err(LucidErr::from("Bad Section Header Insufficient Data"));
    }

    // Store the fully formed SectionHeader structs here
    let mut section_headers: Vec<SectionHeader> = Vec::new();

    // Set the starting offset to where we left off parsing, we can then loop
    // safely from this offset, updating it each iteration, because we've
    // already validated that we have enough data to support the section table
    let mut off = consumed;
    for _ in 0..elf_header.shnum {
        // Create a copy of the data to work with
        let sheader_data = &data[off..off + SEC_HDR_SIZE];

        // Get the name index
        arr32.copy_from_slice(&sheader_data[0x0..0x4]);
        let name = u32::from_le_bytes(arr32);

        // Get the type, we really don't care about checking this value,
        // everyone will have some weird section types from whatever toolchain
        // got built
        arr32.copy_from_slice(&sheader_data[0x4..0x8]);
        let typ = u32::from_le_bytes(arr32);

        // Get the flags
        arr64.copy_from_slice(&sheader_data[0x8..0x10]);
        let flags = u64::from_le_bytes(arr64);

        // Get the addr
        arr64.copy_from_slice(&sheader_data[0x10..0x18]);
        let addr = u64::from_le_bytes(arr64);

        // Get the offset
        arr64.copy_from_slice(&sheader_data[0x18..0x20]);
        let offset = u64::from_le_bytes(arr64);

        // Get the section size
        arr64.copy_from_slice(&sheader_data[0x20..0x28]);
        let size = u64::from_le_bytes(arr64);

        // Get the link
        arr32.copy_from_slice(&sheader_data[0x28..0x2C]);
        let link = u32::from_le_bytes(arr32);

        // Get the section info
        arr32.copy_from_slice(&sheader_data[0x2C..0x30]);
        let info = u32::from_le_bytes(arr32);

        // Get the address alignment of the section
        arr64.copy_from_slice(&sheader_data[0x30..0x38]);
        let addralign = u64::from_le_bytes(arr64);

        // Get the size of fixed entries > 0
        arr64.copy_from_slice(&sheader_data[0x38..0x40]);
        let entsize = u64::from_le_bytes(arr64);

        // Create the finished section header and store it
        let section_header = SectionHeader {
            name,
            typ,
            flags,
            addr,
            offset,
            size,
            link,
            info,
            addralign,
            entsize,
        };

        section_headers.push(section_header);

        // Update the offset
        off += SEC_HDR_SIZE;
    }

    Ok(section_headers)
}


// Parse a static ELF and return our representation
pub fn parse_elf(data: &[u8]) -> Result<Elf, LucidErr> {
    // Create ELF header struct from the data
    let elf_header = parse_elf_header(data)?;

    // Pass the ELF header and the data to parse the program headers
    let program_headers = parse_program_header(&elf_header, data)?;

    // Pass the ELF header and the data to parse the section headers
    let section_headers = parse_section_header(&elf_header, data)?;

    Ok(Elf {
        elf_header,
        program_headers,
        section_headers,
        data: data.to_vec(),
    })
}