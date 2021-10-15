use crate::error::Error;
use crate::result::Result;
use std::convert::TryInto;

pub fn get_bitness(binary: &[u8]) -> Result<u32> {
    let mut bitness_id = 0;
    if let Ok(pe_offset) = get_pe_offset(binary) {
        if pe_offset != 0 && binary.len() as u64 >= pe_offset + 0x6 {
            let bb: [u8; 2] =
                binary[pe_offset as usize + 0x4..pe_offset as usize + 0x6].try_into()?;
            bitness_id = u16::from_le_bytes(bb);
        }
    }
    match bitness_id {
        0x14c => Ok(32),
        0x8664 => Ok(64),
        _ => Err(Error::UnsupportedPEBitnessIDError(bitness_id)),
    }
}

pub fn get_base_address(binary: &[u8]) -> Result<u64> {
    let _base_addr = 0;
    let pe_offset = get_pe_offset(binary)?;
    if pe_offset != 0 && binary.len() >= pe_offset as usize + 0x38 {
        if get_bitness(binary)? == 32 {
            let bb: [u8; 4] =
                binary[pe_offset as usize + 0x34..pe_offset as usize + 0x38].try_into()?;
            return Ok(u32::from_le_bytes(bb) as u64);
        } else if get_bitness(binary)? == 64 {
            let bb: [u8; 8] =
                binary[pe_offset as usize + 0x30..pe_offset as usize + 0x38].try_into()?;
            return Ok(u64::from_le_bytes(bb));
        }
    }
    Err(Error::PEBaseAdressError)
}

pub fn get_pe_offset(binary: &[u8]) -> Result<u64> {
    if binary.len() >= 0x40 {
        let bb: [u8; 2] = binary[0x3c..0x3c + 2].try_into()?;
        let pe_offset = u16::from_le_bytes(bb) as u64;
        return Ok(pe_offset);
    }
    return Ok(0);
}

pub fn get_code_areas(binary: &[u8], pe: &goblin::pe::PE) -> Result<Vec<(u64, u64)>> {
    let mut res = vec![];
    let base_address = get_base_address(binary)?;
    for section in &pe.sections {
        if section.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE != 0 {
            let section_start = base_address + section.virtual_address as u64;
            let mut section_size = section.virtual_size as u64;
            if section_size % 0x1000 != 0 {
                section_size += 0x1000 - (section_size % 0x1000);
                let section_end = section_start + section_size;
                res.push((section_start, section_end));
            }
        }
    }
    Ok(res)
}

pub fn map_binary(binary: &[u8]) -> Result<Vec<u8>> {
    //This is a pretty rough implementation but does the job for now
    let mut mapped_binary = vec![];
    let pe_offset = get_pe_offset(binary)? as usize;
    let mut num_sections = 0;
    let mut section_infos = vec![];
    let mut optional_header_size = 0xF8;
    if binary.len() >= pe_offset + 0x8 {
        num_sections =
            u16::from_le_bytes(binary[pe_offset + 0x6..pe_offset + 0x8].try_into()?) as usize;
        let bitness = get_bitness(binary)?;
        if bitness == 64 {
            optional_header_size = 0x108;
        }
    }
    if binary.len() >= pe_offset + optional_header_size + num_sections * 0x28 {
        for section_index in 0..num_sections {
            let section_offset = section_index * 0x28;
            let slice_start = pe_offset + optional_header_size + section_offset + 0x8;
            let slice_end = pe_offset + optional_header_size + section_offset + 0x8 + 0x10;
            let virt_size = u32::from_le_bytes(binary[slice_start..slice_start + 4].try_into()?);
            let virt_offset =
                u32::from_le_bytes(binary[slice_start + 4..slice_start + 8].try_into()?);
            let raw_size =
                u32::from_le_bytes(binary[slice_start + 8..slice_start + 12].try_into()?);
            let raw_offset = u32::from_le_bytes(binary[slice_start + 12..slice_end].try_into()?);
            let section_info = hashmap! {
                "section_index".to_string() => section_index as u32,
                "virt_size".to_string() => virt_size,
                "virt_offset".to_string() => virt_offset,
                "raw_size".to_string() => raw_size,
                "raw_offset".to_string() => raw_offset
            };
            section_infos.push(section_info);
        }
        let mut max_virt_section_offset = 0;
        let mut min_raw_section_offset = 0xFFFFFFFF;
        if section_infos.len() > 0 {
            for section_info in &section_infos {
                max_virt_section_offset = if max_virt_section_offset
                    > section_info["virt_size"] + section_info["virt_offset"]
                {
                    max_virt_section_offset
                } else {
                    section_info["virt_size"] + section_info["virt_offset"]
                };
                max_virt_section_offset = if max_virt_section_offset
                    > section_info["raw_size"] + section_info["virt_offset"]
                {
                    max_virt_section_offset
                } else {
                    section_info["raw_size"] + section_info["virt_offset"]
                };
                if section_info["raw_offset"] > 0x200 {
                    min_raw_section_offset = if min_raw_section_offset < section_info["raw_offset"]
                    {
                        min_raw_section_offset
                    } else {
                        section_info["raw_offset"]
                    };
                }
            }
        }
        //support up to 100MB for now.
        if max_virt_section_offset > 0 && max_virt_section_offset < 100 * 1024 * 1024 {
            mapped_binary.resize(max_virt_section_offset as usize, 0 as u8);
            if min_raw_section_offset < binary.len() as u32 {
                mapped_binary[0..min_raw_section_offset as usize]
                    .clone_from_slice(&binary[0..min_raw_section_offset as usize]);
            }
        }
        for section_info in &section_infos {
            let mapped_from = section_info["virt_offset"];
            let mapped_to = section_info["virt_offset"] + section_info["raw_size"];
            mapped_binary[mapped_from as usize..mapped_to as usize].clone_from_slice(
                &binary[section_info["raw_offset"] as usize
                    ..section_info["raw_offset"] as usize + section_info["raw_size"] as usize],
            );
            //LOG.debug("Mapping %d: raw 0x%x (0x%x bytes) -> virtual 0x%x (0x%x bytes)",
            //              section_info["section_index"],
            //              section_info["raw_offset"],
            //              section_info["raw_size"],
            //              section_info["virt_offset"],
            //              section_info["virt_size"])
        }
    }
    //LOG.debug("Mapped binary of size %d bytes (%d sections) to memory view of size %d bytes", len(binary), num_sections, len(mapped_binary))
    Ok(mapped_binary)
}
