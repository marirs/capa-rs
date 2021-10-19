use crate::{error::Error, Result};

pub fn get_bitness(binary: &[u8]) -> Result<u32> {
    let elffile = match goblin::Object::parse(binary) {
        Ok(goblin::Object::Elf(elf)) => elf,
        _ => return Err(Error::UnsupportedFormatError)
    };
    let machine_type = elffile.header.e_machine;
    if machine_type == goblin::elf::header::EM_X86_64{
        return Ok(64);
    }
    else if machine_type == goblin::elf::header::EM_386{
        return Ok(32);
    }
    Err(Error::UnsupportedPEBitnessIDError(11))
}

pub fn get_base_address(binary: &[u8]) -> Result<u64> {
    match goblin::Object::parse(binary) {
        Ok(goblin::Object::Elf(elf)) => {
            let mut base_addr = 0 as u64;
            let mut candidates = vec![0xFFFFFFFFFFFFFFFF as u64];
            for section in elf.section_headers{
                if section.sh_addr > 0{
                    candidates.push(section.sh_addr - section.sh_offset);
                }
            }
            if candidates.len()>1{
                base_addr = candidates.iter().min().unwrap().clone();
            }
            return Ok(base_addr);
        },
        Err(e) => Err(Error::ParseError(e)),
        _ => Err(Error::UnsupportedFormatError)
    }
}

pub fn get_code_areas(binary: &[u8], pe: &goblin::elf::Elf) -> Result<Vec<(u64, u64)>> {
    let mut res = vec![];
    let base_address = get_base_address(binary)?;
    for section in &pe.section_headers {
        if section.sh_flags & goblin::elf::section_header::SHF_EXECINSTR as u64 != 0 {
            let section_start = base_address + section.sh_addr;
            let mut section_size = section.sh_size;
            if section_size % section.sh_addralign != 0 {
                section_size += section.sh_addralign - (section_size % section.sh_addralign);
                let section_end = section_start + section_size;
                res.push((section_start, section_end));
            }
        }
    }
    Ok(res)
}

fn align(v: &u64, alignment: &u64) -> u64{
    let remainder = v % alignment;
    if remainder == 0{
        return *v;
    }
    return v + (alignment - remainder);
}

pub fn map_binary(binary: &[u8]) -> Result<Vec<u8>> {
    let elffile = match goblin::Object::parse(binary) {
        Ok(goblin::Object::Elf(elf)) => elf,
        _ => return Err(Error::UnsupportedFormatError)
    };
    let base_addr = get_base_address(binary)?;
    let mut max_virtual_address = 0 as u64;
    let mut min_virtual_address = 0xFFFFFFFFFFFFFFFF as u64;
    let mut min_raw_offset = 0xFFFFFFFFFFFFFFFF as u64;
    for section in &elffile.section_headers{
        if section.sh_addr == 0{
            continue;
        }
        max_virtual_address = max_virtual_address.max(section.sh_size + section.sh_addr);
        min_virtual_address = min_virtual_address.min(section.sh_addr);
        min_raw_offset = min_raw_offset.min(section.sh_offset);
    }
    for segment in &elffile.program_headers{
        if segment.p_vaddr == 0{
            continue;
        }
        max_virtual_address = max_virtual_address.max(segment.p_memsz + segment.p_vaddr);
        min_virtual_address = min_virtual_address.min(segment.p_vaddr);
        min_raw_offset = min_raw_offset.min(segment.p_offset);
    }

    if max_virtual_address == 0{
        return Err(Error::UnsupportedFormatError);
    }
    let virtual_size = max_virtual_address - base_addr;
    let mut mapped_binary = vec![];
    mapped_binary.resize(align(&virtual_size, &0x1000) as usize, 0_u8);
    for segment in elffile.program_headers{
        if segment.p_vaddr == 0{
            continue;
        }
        let rva = segment.p_vaddr - base_addr;
        mapped_binary[rva as usize..(rva + segment.p_filesz) as usize].clone_from_slice(&binary[segment.p_offset as usize..(segment.p_offset+segment.p_filesz) as usize]);
    }
    for section in &elffile.section_headers{
        if section.sh_addr == 0{
            continue;
        }
        let rva = section.sh_addr - base_addr;
        if section.sh_offset+section.sh_size >= binary.len() as u64{
            continue;
        }else{
            mapped_binary[rva as usize..(rva + section.sh_size) as usize].clone_from_slice(&binary[section.sh_offset as usize..(section.sh_offset+section.sh_size) as usize]);
        }
    }
    if min_raw_offset != 0{
        mapped_binary[0 .. min_raw_offset as usize].clone_from_slice(&binary[0..min_raw_offset as usize]);
    }
    Ok(mapped_binary)
}
