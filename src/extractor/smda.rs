#![allow(dead_code, clippy::to_string_in_format_args)]

use std::collections::{BTreeMap, HashMap};
use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    static ref RE_NUMBER_HEX_SPACED: Regex = Regex::new(r"(?P<sign>[+\-]) (?P<num>0x[a-fA-F0-9]+)").unwrap();
    static ref RE_NUMBER_INT_SPACED: Regex = Regex::new(r"(?P<sign>[+\-]) (?P<num>[0-9]+)").unwrap();

    static ref RE_NUMBER_HEX: Regex = Regex::new(r"(?P<sign>[+\-])(?P<num>0x[a-fA-F0-9]+)").unwrap();
    static ref RE_NUMBER_INT: Regex = Regex::new(r"(?P<sign>[+\-])(?P<num>[0-9]+)").unwrap();
}

use smda::{
    function::{Function, Instruction},
    report::DisassemblyReport,
    Disassembler,
};

use crate::{
    consts::{FileFormat, Os},
    error::Error,
    Result,
};

#[derive(Debug, Clone)]
struct InstructionS {
    i: Instruction,
}
impl super::Instruction for InstructionS {
    fn is_mov_imm_to_stack(&self) -> Result<bool> {
        is_mov_imm_to_stack(&self.i)
    }
    fn get_printable_len(&self) -> Result<u64> {
        Ok(self.i.get_printable_len()?)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[derive(Debug, Clone)]
struct FunctionS {
    f: Function,
}

impl super::Function for FunctionS {
    fn inrefs(&self) -> &Vec<u64> {
        &self.f.inrefs
    }
    fn blockrefs(&self) -> &HashMap<u64, Vec<u64>> {
        &self.f.blockrefs
    }
    fn offset(&self) -> u64 {
        self.f.offset
    }

    fn get_blocks(&self) -> Result<BTreeMap<u64, Vec<Box<dyn super::Instruction>>>> {
        let mut res = BTreeMap::<u64, Vec<Box<dyn super::Instruction>>>::new();
        for (u, b) in self.f.get_blocks()? {
            let mut instr: Vec<Box<dyn super::Instruction>> = vec![];
            for i in b {
                instr.push(Box::new(InstructionS { i: i.clone() }));
            }
            res.insert(*u, instr);
        }
        Ok(res)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[derive(Debug, Clone)]
pub struct Extractor {
    pub report: DisassemblyReport,
    buf: Vec<u8>,
    path: String,
}

impl super::Extractor for Extractor {
    fn is_dot_net(&self) -> bool {
        false
    }

    fn get_base_address(&self) -> Result<u64> {
        Ok(self.report.base_addr)
    }

    fn format(&self) -> FileFormat {
        match self.report.format {
            smda::FileFormat::PE => FileFormat::PE,
            smda::FileFormat::ELF => FileFormat::ELF,
        }
    }

    fn bitness(&self) -> u32 {
        self.report.bitness
    }

    fn extract_global_features(&self) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        Ok(vec![
            (
                crate::rules::features::Feature::Os(crate::rules::features::OsFeature::new(
                    &self.extract_os()?.to_string(),
                    "",
                )?),
                0,
            ),
            (
                crate::rules::features::Feature::Arch(crate::rules::features::ArchFeature::new(
                    &self.extract_arch()?.to_string(),
                    "",
                )?),
                0,
            ),
        ])
    }

    fn extract_file_features(&self) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        //        res.extend(self.extract_file_embedded_pe()?);
        res.extend(self.extract_file_export_names()?);
        res.extend(self.extract_file_import_names()?);
        res.extend(self.extract_file_section_names()?);
        res.extend(self.extract_file_embedded_pe()?);
        res.extend(self.extract_file_strings()?);
        //        res.extend(self.extract_file_function_names(pbytes)?);
        res.extend(self.extract_file_format()?);
        Ok(res)
    }

    fn get_functions(&self) -> Result<BTreeMap<u64, Box<dyn super::Function>>> {
        let mut res = BTreeMap::<u64, Box<dyn super::Function>>::new();
        for (u, f) in self.report.get_functions()? {
            res.insert(*u, Box::new(FunctionS { f: f.clone() }));
        }
        Ok(res)
    }

    fn extract_function_features(
        &self,
        f: &Box<dyn super::Function>,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![]; //extract function calls to
        for inref in f.inrefs() {
            res.push((
                crate::rules::features::Feature::Characteristic(
                    crate::rules::features::CharacteristicFeature::new("calls to", "")?,
                ),
                *inref,
            ));
        }
        //parse if a function has a loop
        let mut vertices_names = std::collections::HashSet::new();
        let mut edges = vec![];
        for (bb_from, bb_tos) in f.blockrefs() {
            for bb_to in bb_tos {
                vertices_names.insert(*bb_from);
                vertices_names.insert(*bb_to);
                edges.push((*bb_from, *bb_to))
            }
        }
        if !edges.is_empty() && self.has_loop(&vertices_names, &edges)? {
            res.push((
                crate::rules::features::Feature::Characteristic(
                    crate::rules::features::CharacteristicFeature::new("loop", "")?,
                ),
                f.offset(),
            ));
        }
        Ok(res)
    }

    fn get_basic_blocks(
        &self,
        f: &Box<dyn super::Function>,
    ) -> Result<BTreeMap<u64, Vec<Box<dyn super::Instruction>>>> {
        f.get_blocks()
    }

    fn get_instructions<'a>(
        &self,
        _f: &Box<dyn super::Function>,
        bb: &'a (&u64, &Vec<Box<dyn super::Instruction>>),
    ) -> Result<&'a Vec<Box<dyn super::Instruction>>> {
        Ok(bb.1)
    }

    fn extract_basic_block_features(
        &self,
        f: &Box<dyn super::Function>,
        bb: &(&u64, &Vec<Box<dyn super::Instruction>>),
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![(
            crate::rules::features::Feature::BasicBlock(
                crate::rules::features::BasicBlockFeature::new()?,
            ),
            *bb.0,
        )];
        if f.blockrefs().contains_key(bb.0) && f.blockrefs()[bb.0].contains(bb.0) {
            res.push((
                crate::rules::features::Feature::Characteristic(
                    crate::rules::features::CharacteristicFeature::new("tight loop", "")?,
                ),
                *bb.0,
            ));
        }
        let mut count = 0;
        for instr in bb.1 {
            if instr.is_mov_imm_to_stack()? {
                count += instr.get_printable_len()?;
            }
            if count > 8 {
                //MIN_STACKSTRING_LEN
                res.push((
                    crate::rules::features::Feature::Characteristic(
                        crate::rules::features::CharacteristicFeature::new("stack string", "")?,
                    ),
                    *bb.0,
                ));
            }
        }
        Ok(res)
    }

    fn extract_insn_features(
        &self,
        f: &Box<dyn super::Function>,
        insn: &Box<dyn super::Instruction>,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let f: &FunctionS = f.as_any().downcast_ref::<FunctionS>().unwrap();
        let insn: &InstructionS = insn.as_any().downcast_ref::<InstructionS>().unwrap();
        let mut res = vec![];
        res.extend(self.extract_insn_api_features(&f.f, &insn.i)?);
        res.extend(self.extract_insn_number_features(&f.f, &insn.i)?);
        res.extend(self.extract_insn_string_features(&f.f, &insn.i)?);
        res.extend(self.extract_insn_bytes_features(&f.f, &insn.i)?);
        res.extend(self.extract_insn_offset_features(&f.f, &insn.i)?);
        res.extend(self.extract_insn_nzxor_characteristic_features(&f.f, &insn.i)?);
        res.extend(self.extract_insn_obfs_call_plus_5_characteristic_features(&f.f, &insn.i)?);
        res.extend(self.extract_insn_mnemonic_features(&f.f, &insn.i)?);
        res.extend(self.extract_insn_peb_access_characteristic_features(&f.f, &insn.i)?);
        res.extend(self.extract_insn_cross_section_cflow(&f.f, &insn.i)?);
        res.extend(self.extract_insn_segment_access_features(&f.f, &insn.i)?);
        res.extend(self.extract_function_calls_from(&f.f, &insn.i)?);
        res.extend(self.extract_function_indirect_call_characteristic_features(&f.f, &insn.i)?);
        res.extend(self.extract_file_format()?);
        res.extend(self.extract_global_features()?);
        Ok(res)
    }
}

impl Extractor {
    pub fn new(
        path: &str,
        high_accuracy: bool,
        resolve_tailcalls: bool,
        data: &Vec<u8>,
    ) -> Result<Extractor> {
        Ok(Extractor {
            report: Disassembler::disassemble_file(
                path,
                high_accuracy,
                resolve_tailcalls,
                Some(data),
            )?,
            buf: data.clone(),
            path: path.to_string(),
        })
    }

    pub fn get_buf(&self) -> Result<&[u8]> {
        Ok(&self.buf)
    }

    pub fn get_elf_os(elf: &goblin::elf::Elf) -> Result<Os> {
        match elf.header.e_ident[7] {
            0x00 => Ok(Os::LINUX),
            0x01 => Ok(Os::HPUX),
            0x02 => Ok(Os::NETBSD),
            0x03 => Ok(Os::LINUX),
            0x04 => Ok(Os::HURD),
            0x06 => Ok(Os::SOLARIS),
            0x07 => Ok(Os::AIX),
            0x08 => Ok(Os::IRIX),
            0x09 => Ok(Os::FREEBSD),
            0x0A => Ok(Os::TRU64),
            0x0B => Ok(Os::MODESTO),
            0x0C => Ok(Os::OPENBSD),
            0x0D => Ok(Os::OPENVMS),
            0x0E => Ok(Os::NSK),
            0x0F => Ok(Os::AROS),
            0x10 => Ok(Os::FENIXOS),
            0x11 => Ok(Os::CLOUD),
            _ => {
                // For Unknown ELF OS, also assume Linux as fallback
                Ok(Os::LINUX)
            }
        }
    }
    pub fn extract_os(&self) -> Result<Os> {
        match goblin::Object::parse(&self.buf)? {
            goblin::Object::Elf(elf) => Extractor::get_elf_os(&elf),
            goblin::Object::PE(_) => Ok(Os::WINDOWS),
            _ => Err(Error::UnsupportedOsError),
        }
    }

    pub fn extract_arch(&self) -> Result<crate::FileArchitecture> {
        Ok(self.report.architecture)
    }

    pub fn has_loop(
        &self,
        vertices_names: &std::collections::HashSet<u64>,
        edges: &[(u64, u64)],
    ) -> Result<bool> {
        let mut vertices = std::collections::HashMap::new();
        let mut graph = petgraph::graph::Graph::<u64, ()>::new(); // directed and unlabeled
        for n in vertices_names {
            vertices.insert(n, graph.add_node(*n));
        }
        graph.extend_with_edges(
            edges
                .iter()
                .map(|(a, b)| (vertices[a], vertices[b]))
                .collect::<Vec<(petgraph::graph::NodeIndex, petgraph::graph::NodeIndex)>>(),
        );
        let scc = petgraph::algo::kosaraju_scc(&graph);
        let mut res = false;
        for s in &scc {
            res |= s.len() >= 2 //threshold
        }
        Ok(res)
    }

    fn extract_file_format(&self) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        res.push((
            crate::rules::features::Feature::Format(crate::rules::features::FormatFeature::new(
                if let smda::FileFormat::PE = self.report.format {
                    "pe"
                } else {
                    "elf"
                },
                "",
            )?),
            0,
        ));
        Ok(res)
    }

    fn extract_file_embedded_pe(&self) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        for (mz_offset, _pe_offset, _key) in
            Extractor::find_embedded_pe_headers(&self.report.buffer)
        {
            res.push((
                crate::rules::features::Feature::Characteristic(
                    crate::rules::features::CharacteristicFeature::new("embedded pe", "")?,
                ),
                mz_offset,
            ));
        }
        Ok(res)
    }

    pub fn extract_file_section_names(
        &self,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        for (n, b, _e) in &self.report.sections {
            res.push((
                crate::rules::features::Feature::Section(
                    crate::rules::features::SectionFeature::new(n.trim_matches(char::from(0)), "")?,
                ),
                *b,
            ));
        }
        Ok(res)
    }

    pub fn extract_file_export_names(&self) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        for (e, o, ree) in &self.report.exports {
            match ree {
                None => {
                    res.push((
                        crate::rules::features::Feature::Export(
                            crate::rules::features::ExportFeature::new(e, "")?,
                        ),
                        *o as u64,
                    ));
                }
                Some(re) => {
                    res.push((
                        crate::rules::features::Feature::Export(
                            crate::rules::features::ExportFeature::new(re, "")?,
                        ),
                        *o as u64,
                    ));
                    res.push((
                        crate::rules::features::Feature::Characteristic(
                            crate::rules::features::CharacteristicFeature::new(
                                "forwarded export",
                                "",
                            )?,
                        ),
                        *o as u64,
                    ));
                }
            }
        }
        Ok(res)
    }

    pub fn extract_file_import_names(&self) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        for (d, f, o) in &self.report.imports {
            for n in generate_symbols(&Some(d.to_string()), &Some(f.to_string()))? {
                res.push((
                    crate::rules::features::Feature::Import(
                        crate::rules::features::ImportFeature::new(&n, "")?,
                    ),
                    *o as u64,
                ));
            }
        }
        Ok(res)
    }

    fn extract_file_strings(&self) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        for (s, a) in extract_file_strings(&self.buf)? {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                continue;
            }
            res.push((
                crate::rules::features::Feature::String(
                    crate::rules::features::StringFeature::new(trimmed, "")?,
                ),
                a,
            ));
        }
        Ok(res)
    }

    pub fn extract_function_indirect_call_characteristic_features(
        &self,
        _f: &Function,
        insn: &Instruction,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        if insn.mnemonic != "call" {
            return Ok(res);
        }
        if let Some(o) = &insn.operands {
            if o.starts_with("0x") {
                return Ok(res);
            }
            if o.contains("qword ptr") && o.contains("rip") {
                return Ok(res);
            }
            if o.starts_with("dword ptr [0x") {
                return Ok(res);
            }
            //# call edx
            //# call dword ptr [eax+50h]
            //# call qword ptr [rsp+78h]
            res.push((
                crate::rules::features::Feature::Characteristic(
                    crate::rules::features::CharacteristicFeature::new("indirect call", "")?,
                ),
                insn.offset,
            ));
        }
        Ok(res)
    }

    pub fn extract_function_calls_from(
        &self,
        f: &Function,
        insn: &Instruction,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        if insn.mnemonic != "call" {
            return Ok(res);
        }

        if f.outrefs.contains_key(&insn.offset) {
            for outref in &f.outrefs[&insn.offset] {
                res.push((
                    crate::rules::features::Feature::Characteristic(
                        crate::rules::features::CharacteristicFeature::new("calls from", "")?,
                    ),
                    *outref,
                ));
                if outref == &f.offset {
                    //if we found a jump target and it's the function address
                    //mark as recursive
                    res.push((
                        crate::rules::features::Feature::Characteristic(
                            crate::rules::features::CharacteristicFeature::new(
                                "recursive call",
                                "",
                            )?,
                        ),
                        *outref,
                    ));
                }
            }
        }
        if f.apirefs.contains_key(&insn.offset) {
            res.push((
                crate::rules::features::Feature::Characteristic(
                    crate::rules::features::CharacteristicFeature::new("calls from", "")?,
                ),
                insn.offset,
            ));
        }
        Ok(res)
    }
    pub fn extract_insn_segment_access_features(
        &self,
        _f: &Function,
        insn: &Instruction,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        if let Some(o) = &insn.operands {
            let operands: Vec<String> = o.split(',').map(|s| s.trim().to_string()).collect();
            for operand in operands {
                if operand.contains("fs:") {
                    res.push((
                        crate::rules::features::Feature::Characteristic(
                            crate::rules::features::CharacteristicFeature::new("fs access", "")?,
                        ),
                        insn.offset,
                    ));
                }
                if operand.contains("gs:") {
                    res.push((
                        crate::rules::features::Feature::Characteristic(
                            crate::rules::features::CharacteristicFeature::new("gs access", "")?,
                        ),
                        insn.offset,
                    ));
                }
            }
        }
        Ok(res)
    }

    pub fn extract_insn_cross_section_cflow(
        &self,
        f: &Function,
        insn: &Instruction,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        if ["call", "jmp"].contains(&&insn.mnemonic[..]) {
            if f.apirefs.contains_key(&insn.offset) {
                return Ok(res);
            }

            if f.outrefs.contains_key(&insn.offset) {
                for target in &f.outrefs[&insn.offset] {
                    if self.report.get_section(&insn.offset)? != self.report.get_section(target)? {
                        res.push((
                            crate::rules::features::Feature::Characteristic(
                                crate::rules::features::CharacteristicFeature::new(
                                    "cross section flow",
                                    "",
                                )?,
                            ),
                            insn.offset,
                        ));
                    }
                }
            } else if let Some(o) = &insn.operands {
                // if o.starts_with("0x") {
                //     let target = u64::from_str_radix(&o[2..], 16)?;
                if let Some(x) = o.strip_prefix("0x") {
                    let target = u64::from_str_radix(x, 16)?;
                    if self.report.get_section(&insn.offset)? != self.report.get_section(&target)? {
                        res.push((
                            crate::rules::features::Feature::Characteristic(
                                crate::rules::features::CharacteristicFeature::new(
                                    "cross section flow",
                                    "",
                                )?,
                            ),
                            insn.offset,
                        ));
                    }
                }
            }
        }
        Ok(res)
    }

    pub fn extract_insn_peb_access_characteristic_features(
        &self,
        _f: &Function,
        insn: &Instruction,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        if !["push", "mov"].contains(&&insn.mnemonic[..]) {
            return Ok(res);
        }
        if let Some(o) = &insn.operands {
            let operands: Vec<String> = o.split(',').map(|s| s.trim().to_string()).collect();
            for operand in operands {
                if (operand.contains("fs:") && operand.contains("0x30"))
                    || (operand.contains("gs:") && operand.contains("0x60"))
                {
                    res.push((
                        crate::rules::features::Feature::Characteristic(
                            crate::rules::features::CharacteristicFeature::new("peb access", "")?,
                        ),
                        insn.offset,
                    ));
                }
            }
        }
        Ok(res)
    }

    pub fn extract_insn_mnemonic_features(
        &self,
        _f: &Function,
        insn: &Instruction,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        Ok(vec![(
            crate::rules::features::Feature::Mnemonic(
                crate::rules::features::MnemonicFeature::new(&insn.mnemonic, "")?,
            ),
            insn.offset,
        )])
    }

    pub fn extract_insn_nzxor_characteristic_features(
        &self,
        f: &Function,
        insn: &Instruction,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        if !["xor", "xorpd", "xorps", "pxor"].contains(&&insn.mnemonic[..]) {
            return Ok(res);
        }
        if let Some(o) = &insn.operands {
            let operands: Vec<String> = o.split(',').map(|s| s.trim().to_string()).collect();
            if operands[0] == operands[1] {
                return Ok(res);
            }
        }
        if is_security_cookie(f, insn)? {
            return Ok(res);
        }

        res.push((
            crate::rules::features::Feature::Characteristic(
                crate::rules::features::CharacteristicFeature::new("nzxor", "")?,
            ),
            insn.offset,
        ));
        Ok(res)
    }

    pub fn extract_insn_obfs_call_plus_5_characteristic_features(
        &self,
        _f: &Function,
        insn: &Instruction,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        if &insn.mnemonic[..] != "call" {
            return Ok(res);
        }
        if let Some(o) = &insn.operands {
            if !o.starts_with("0x") {
                return Ok(res);
            }
            if u64::from_str_radix(&o[2..], 16)? == insn.offset + 5 {
                res.push((
                    crate::rules::features::Feature::Characteristic(
                        crate::rules::features::CharacteristicFeature::new("call $+5", "")?,
                    ),
                    insn.offset,
                ));
            }
        }
        Ok(res)
    }

    pub fn extract_insn_offset_features(
        &self,
        f: &Function,
        insn: &Instruction,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        //# examples:
        //#
        //#     mov eax, [esi + 4]
        //#     mov eax, [esi + ecx + 16384]
        if let Some(o) = &insn.operands {
            let operands: Vec<String> = o.split(',').map(|s| s.trim().to_string()).collect();
            for (i, operand) in operands.iter().enumerate() {
                if !insn.mnemonic.contains("lea") && !operand.contains("ptr") {
                    continue;
                }
                //NOTE not sure
                if
                /*operand.contains("esp") ||*/
                operand.contains("ebp") || operand.contains("rbp") {
                    continue;
                }
                let mut number = 0;

                let number_hex = RE_NUMBER_HEX_SPACED.captures(operand);
                let number_int = RE_NUMBER_INT_SPACED.captures(operand);
                if let Some(n) = number_hex {
                    number = i128::from_str_radix(&n["num"][2..], 16)?;
                    if &n["sign"] == "-" {
                        number *= -1;
                    }
                } else if let Some(n) = number_int {
                    number = (n["num"]).parse::<i128>()?;
                    if &n["sign"] == "-" {
                        number *= -1;
                    }
                }
                res.push((
                    crate::rules::features::Feature::Offset(
                        crate::rules::features::OffsetFeature::new(f.bitness, &number, "")?,
                    ),
                    insn.offset,
                ));
                res.push((
                    crate::rules::features::Feature::OperandOffset(
                        crate::rules::features::OperandOffsetFeature::new(&i, &number, "")?,
                    ),
                    insn.offset,
                ));

                if insn.mnemonic.contains("lea") {
                    res.push((
                        crate::rules::features::Feature::Number(
                            crate::rules::features::NumberFeature::new(f.bitness, &number, "")?,
                        ),
                        insn.offset,
                    ));
                }
            }
        }
        Ok(res)
    }

    pub fn extract_insn_string_features(
        &self,
        _f: &Function,
        insn: &Instruction,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        //# example:
        //#
        //#     push    offset aAcr     ; "ACR  > "
        for data_ref in insn.get_data_refs(&self.report)? {
            for v in derefs(&self.report, &data_ref)? {
                let string_read = read_string(&self.report, &v)?;
                let trimmed = string_read.trim();
                if trimmed.is_empty() {
                    continue;
                }
                res.push((
                    crate::rules::features::Feature::String(
                        crate::rules::features::StringFeature::new(
                            trimmed.trim_end_matches('\x00'),
                            "",
                        )?,
                    ),
                    insn.offset,
                ));
            }
        }
        Ok(res)
    }

    pub fn extract_insn_bytes_features(
        &self,
        _f: &Function,
        insn: &Instruction,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];

        for data_ref in insn.get_data_refs(&self.report)? {
            for v in derefs(&self.report, &data_ref)? {
                let bytes_read = read_bytes(&self.report, &v, 0x100)?;
                if all_zeros(bytes_read)? || is_padding(bytes_read)? {
                    continue;
                }
                res.push((
                    crate::rules::features::Feature::Bytes(
                        crate::rules::features::BytesFeature::new(bytes_read, "")?,
                    ),
                    insn.offset,
                ));
            }
        }
        Ok(res)
    }

    fn parse_operand_to_number(&self, operand: &str) -> Option<i128> {
        let operand = operand.trim();

        // case 1: if operand is like 0x1234
        if let Some(x) = operand.strip_prefix("0x") {
            return i128::from_str_radix(x, 16).ok();
        }

        // case 2: if operand is like 1234h
        if let Some(stripped_operand) = operand.strip_suffix('h') {
            return i128::from_str_radix(stripped_operand, 16).ok();
        }

        // case 3: if operand is like +0x1234
        //if start with sign apply this logic
        if operand.starts_with('-') || operand.starts_with('+') {
            if let Some(captures) = RE_NUMBER_HEX.captures(operand) {
                let sign = &captures["sign"];
                let number = &captures["num"];
                let value = i128::from_str_radix(number, 16).ok()?;
                return Some(if sign == "-" { -value } else { value });
            }
            if let Some(captures) = RE_NUMBER_INT.captures(operand) {
                let sign = &captures["sign"];
                let number = &captures["num"];
                let value = number.parse::<i128>().ok()?;
                return Some(if sign == "-" { -value } else { value });
            }
        }

        // case 4: if operand is like 1234
        if let Ok(val) = operand.parse::<i128>() {
            return Some(val);
        }

        // case 5: if operand is like 0x1234
        i128::from_str_radix(operand, 16).ok()
    }

    pub fn extract_insn_number_features(
        &self,
        f: &Function,
        insn: &Instruction,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        if let Some(o) = &insn.operands {
            let operands: Vec<String> = o.split(',').map(|s| s.trim().to_string()).collect();

            if insn.mnemonic == "add" && ["esp", "rsp"].contains(&operands[0].as_str()) {
                return Ok(vec![]);
            }

            for (i, operand) in operands.iter().enumerate() {
                if let Some(s) = self.parse_operand_to_number(operand) {
                    if s >= 0
                    {
                        res.push((
                            crate::rules::features::Feature::Number(
                                crate::rules::features::NumberFeature::new(f.bitness, &s, "")?,
                            ),
                            insn.offset,
                        ));
                    }
                    else
                    {
                        let masked_value = (s as u32) as i128;  // Convierte a u32 y de vuelta a i128
                        res.push((
                            crate::rules::features::Feature::Number(
                                crate::rules::features::NumberFeature::new(f.bitness, &masked_value, "")?,
                            ),
                            insn.offset,
                        ));
                    }
                    res.push((
                        crate::rules::features::Feature::OperandNumber(
                            crate::rules::features::OperandNumberFeature::new(&i, &s, "")?,
                        ),
                        insn.offset,
                    ));
                }
            }
        }
        Ok(res)
    }

    pub fn extract_insn_api_features(
        &self,
        f: &Function,
        insn: &Instruction,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        let va = self.report.base_addr + insn.offset;

        if let Some((dll, api)) = f.apirefs.get(&insn.offset) {
            if let Some(api_name) = api {
                let highest_addr = self.find_highest_address_for_symbol(api_name);
                if let Some(addr) = highest_addr {
                    self.push_api_features(&mut res, dll, api, addr)?;
                } else {
                    self.push_api_features(&mut res, dll, api, va)?;
                }
            } else {
                self.push_api_features(&mut res, dll, api, va)?;
            }
            return Ok(res);
        }

        if let Some(targets) = f.outrefs.get(&insn.offset) {
            let mut api_candidates = Vec::new();

            for target in targets.iter().rev() {
                if let Some((dll, api)) = self.report.addr_to_api.get(target) {
                    api_candidates.push((*target, dll.clone(), api.clone()));
                }
            }

            if !api_candidates.is_empty() {
                let best_candidate = api_candidates.iter().max_by_key(|(addr, _, _)| *addr).unwrap();
                let (mut best_addr, dll, api) = best_candidate.clone();

                // FIX: api es Option<String>, desenvolverlo
                if let Some(api_name) = &api {
                    if let Some(highest) = self.find_highest_address_for_symbol(api_name) {
                        best_addr = highest;
                    }
                }

                self.push_api_features(&mut res, &dll, &api, best_addr)?;
                return Ok(res);
            }
        }

        // fallback: thunk chain resolution
        let mut current_function = f;
        let mut current_instruction = insn;

        for _ in 0..5 {
            if let Some(targets) = current_function.outrefs.get(&current_instruction.offset) {
                if targets.len() != 1 {
                    break;
                }

                let chain_target = targets[0];
                let referenced_function = match self.report.get_function(chain_target) {
                    Ok(func) => func,
                    Err(_) => break,
                };

                if referenced_function.is_api_thunk()? {
                    if let Some((dll, api)) = referenced_function.apirefs.get(&chain_target) {
                        if let Some(api_name) = api {
                            if let Some(highest) = self.find_highest_address_for_symbol(api_name) {
                                self.push_api_features(&mut res, dll, api, highest)?;
                                return Ok(res);
                            }
                        }

                        self.push_api_features(&mut res, dll, api, chain_target)?;
                    }
                    break;
                }

                if referenced_function.get_num_instructions()? == 1
                    && referenced_function.get_num_outrefs()? == 1
                {
                    current_function = referenced_function;
                    current_instruction = referenced_function.get_instructions()?[0];
                }
                else
                {
                    break;
                }
            } else {
                break;
            }
        }

        Ok(res)
    }

    fn find_highest_address_for_symbol(&self, symbol_name: &str) -> Option<u64> {
        let mut addresses = Vec::new();

        for (addr, (_, api)) in &self.report.addr_to_api {
            if let Some(api_name) = api {
                if api_name == symbol_name {
                    addresses.push(*addr);
                }
            }
        }

        addresses.into_iter().max()
    }

    fn push_api_features(
        &self,
        res: &mut Vec<(crate::rules::features::Feature, u64)>,
        dll: &Option<String>,
        api: &Option<String>,
        va: u64,
    ) -> Result<()> {
        for name in generate_symbols(dll, api)? {
            res.push((
                crate::rules::features::Feature::Api(
                    crate::rules::features::ApiFeature::new(&name, "")?,
                ),
                va,
            ));
        }
        Ok(())
    }

    fn xor_static(data: &[u8], i: u8) -> Result<Vec<u8>> {
        let mut res = vec![];
        for c in data {
            res.push(c ^ i);
        }
        Ok(res)
    }

    fn find_embedded_pe_headers(pbytes: &[u8]) -> Vec<(u64, u64, u8)> {
        let mut results = Vec::new();
        let start_offset = 64usize;
        let end = pbytes.len();

        let end_safe_zone = if end > 0x40 { end - 0x40 } else { 0 };
        let mut current_offset = start_offset;
        while current_offset < end_safe_zone {
            if pbytes[current_offset + 0x3E] == pbytes[current_offset + 0x3F] {
                let key = pbytes[current_offset + 0x3E];

                if pbytes[current_offset] ^ key == b'M' && pbytes[current_offset + 1] ^ key == b'Z'
                {
                    let e_lfanew = u32::from_le_bytes([
                        pbytes[current_offset + 0x3C] ^ key,
                        pbytes[current_offset + 0x3D] ^ key,
                        0,
                        0,
                    ]) as usize;

                    if current_offset + e_lfanew + 0x18 <= end_safe_zone
                        && pbytes[current_offset + e_lfanew] ^ key == b'P'
                        && pbytes[current_offset + e_lfanew + 1] ^ key == b'E'
                        && pbytes[current_offset + e_lfanew + 2] == key
                        && pbytes[current_offset + e_lfanew + 3] == key
                    {
                        results.push((
                            current_offset as u64,
                            (current_offset + e_lfanew) as u64,
                            key,
                        ));
                        current_offset = current_offset + e_lfanew + 4;
                        continue;
                    }
                }
            }
            current_offset += 1;
        }

        results
    }

    fn xor_with_key(bytes: &[u8], key: u8) -> Vec<u8> {
        bytes.iter().map(|&b| b ^ key).collect()
    }

    fn _carve_pe(pbytes: &[u8], offset: u64) -> Result<Vec<(u64, u64)>> {
        let mut mz_xor = vec![];
        for key in 0..255 {
            mz_xor.push((
                Extractor::xor_static(b"MZ", key)?,
                Extractor::xor_static(b"PE", key)?,
                key,
            ));
        }

        let pblen = pbytes.len();
        let mut todo = vec![];

        // Buscar patrones MZ XORed
        for (mzx, pex, key) in mz_xor {
            if let Some(relative_pos) = pbytes[offset as usize..]
                .windows(mzx.len())
                .position(|window| window == mzx)
            {
                let absolute_pos = offset as usize + relative_pos;  // ← CORREGIR: posición absoluta
                todo.push((absolute_pos, mzx, pex, key));
            }
        }

        let mut res = vec![];
        while let Some((off, mzx, pex, key)) = todo.pop() {
            // The MZ header has one field we will check
            let e_lfanew_offset = off + 0x3C;
            if e_lfanew_offset + 4 > pblen {
                continue;
            }

            let ppp: [u8; 4] = Extractor::xor_static(&pbytes[e_lfanew_offset..e_lfanew_offset + 4], key)?
                .try_into()
                .map_err(|_| Error::InvalidRule(line!(), "Failed to parse e_lfanew".to_string()))?;

            let pe_offset_value = u32::from_le_bytes(ppp);

            if off + 1 < pblen {
                if let Some(relative_pos) = pbytes[off + 1..]
                    .windows(mzx.len())
                    .position(|window| window == mzx)
                {
                    let next_absolute_pos = off + 1 + relative_pos;  // ← CORREGIR: posición absoluta
                    todo.push((next_absolute_pos, mzx, pex.clone(), key));
                }
            }

            let pe_header_offset = off + pe_offset_value as usize;
            if pe_header_offset + 2 > pblen {
                continue;
            }
            if pbytes[pe_header_offset..pe_header_offset + 2] == pex {
                res.push((off as u64, key as u64));
            }
        }
        Ok(res)
    }
}

pub fn is_mov_imm_to_stack(ins: &Instruction) -> Result<bool> {
    if !ins.mnemonic.starts_with("mov") {
        return Ok(false);
    }

    if let Ok((dst, src)) = get_operands(ins) {
        if u64::from_str_radix(&src[2..], 16).is_ok() {
            for regname in ["ebp", "rbp", "esp", "rsp"] {
                if dst.contains(regname) {
                    return Ok(false);
                }
            }
        }
        return Ok(true);
    }
    Ok(false)
}

pub fn get_operands(ins: &Instruction) -> Result<(String, String)> {
    if let Some(s) = &ins.operands {
        let parts: Vec<&str> = s.split(',').collect();
        if parts.len() > 1 {
            return Ok((parts[0].to_string(), parts[1].to_string()));
        } else {
            return Ok((parts[0].to_string(), "".to_string()));
        }
    }
    Ok(("".to_string(), "".to_string()))
}

fn clean_dll_name(dll_name: &str) -> String {
    let mut clean = dll_name.to_string();

    // Remove common prefixes
    if clean.ends_with(".so.6") {
        clean = clean[..clean.len() - 5].to_string();
    } else if clean.ends_with(".so") {
        clean = clean[..clean.len() - 3].to_string();
    } else if clean.ends_with(".dll") {
        clean = clean[..clean.len() - 4].to_string();
    }

    clean
}


pub fn generate_symbols(dll: &Option<String>, symbol: &Option<String>) -> Result<Vec<String>> {
    let mut res = vec![];
    let symbol_name = symbol.clone().ok_or_else(|| Error::InvalidRule(line!(), file!().to_string()))?;

    // Add simple symbol if it does not start with #
    if !symbol_name.starts_with('#') {
        res.push(symbol_name.clone());
    }

    // DLL.symbol
    if let Some(dll_ref) = dll {
        let dll_clean = clean_dll_name(dll_ref);
        let dll_symbol = format!("{}.{}", dll_clean, symbol_name);
        if dll_symbol != symbol_name {
            res.push(dll_symbol);
        }
    }

    // A/W variants para APIs Windows
    if !symbol_name.starts_with("_Z") && (symbol_name.ends_with('A') || symbol_name.ends_with('W')) {
        let base_name = &symbol_name[..symbol_name.len() - 1];
        if !res.contains(&base_name.to_string()) {
            res.push(base_name.to_string());
        }
        if let Some(dll_ref) = dll {
            let dll_clean = clean_dll_name(dll_ref);
            res.push(format!("{}.{}", dll_clean, base_name));
        }
    }
    Ok(res)
}

pub fn derefs(report: &DisassemblyReport, p: &u64) -> Result<Vec<u64>> {
    let mut res = vec![];
    let mut depth = 0;
    let mut pp = *p;
    loop {
        if !report.is_addr_within_memory_image(&pp)? {
            break;
        }
        res.push(pp);

        let bytes_: [u8; 4] = read_bytes(report, &pp, 4)?.try_into()?;
        let val = u32::from_le_bytes(bytes_) as u64;
        // sanity: pointer points to self
        if val == pp {
            break;
        }
        //sanity: avoid chains of pointers that are unreasonably deep
        depth += 1;
        if depth > 10 {
            break;
        }
        pp = val;
    }
    Ok(res)
}

pub fn read_bytes<'a>(
    report: &'a DisassemblyReport,
    offset: &u64,
    num_bytes: usize,
) -> Result<&'a [u8]> {
    let rva = offset - report.base_addr;
    let buffer_end = report.buffer.len();
    let mut end_of_string = rva + num_bytes as u64;

    // If end_of_string exceeds buffer_end, adjust it to buffer_end
    if end_of_string > buffer_end as u64 {
        // println!(
        //    "Buffer overflow error end_of_string: {} buffer_end: {}, rva: {}, num_bytes: {}. Force end.",
        //     end_of_string, buffer_end, rva, num_bytes
        // );
        end_of_string = buffer_end as u64;
    }

    // Ensure that rva does not exceed the size of the buffer
    if rva > buffer_end as u64 {
        // println!("Offset out of buffer range rva: {} buffer_end: {}", rva, buffer_end);
        return Err(Error::BufferOverflowError);
    }

    Ok(&report.buffer[rva as usize..end_of_string as usize])
}

pub fn read_string(report: &DisassemblyReport, offset: &u64) -> Result<String> {
    let alen = detect_ascii_len(report, offset)?;
    if alen > 1 {
        let bytes = read_bytes(report, offset, alen)?;
        return Ok(std::str::from_utf8(bytes)?.to_string());
    }
    let ulen = detect_unicode_len(report, offset)?;
    if ulen > 2 {
        let bytes = read_bytes(report, offset, ulen)?;
        let utf16_units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|arr| u16::from_le_bytes([arr[0], arr[1]]))
            .collect();
        return Ok(std::string::String::from_utf16(&utf16_units)?);
    }
    Ok("".to_string())
}

pub fn detect_ascii_len(report: &DisassemblyReport, offset: &u64) -> Result<usize> {
    let buffer_len = report.buffer.len() as u64;
    let rva = offset.checked_sub(report.base_addr).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            "Offset is out of bounds relative to the base address",
        )
    })?;

    if rva as usize >= report.buffer.len() {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "RVA is beyond buffer length",
        ))?;
    }

    let ascii_len = report.buffer[rva as usize..]
        .iter()
        .take_while(|&&ch| ch != 0 && ch.is_ascii())
        .take_while(|&&ch| b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+, -./:;<=>?@[\\]^_`{|}~ \r\n".contains(&ch))
        .count();

    if rva + ascii_len as u64 >= buffer_len {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Buffer overflow detected while detecting ASCII length",
        ))?;
    }

    Ok(ascii_len)
}

pub fn detect_unicode_len(report: &DisassemblyReport, offset: &u64) -> Result<usize> {
    let mut unicode_len = 0;
    let mut rva = offset - report.base_addr;
    let mut ch = report.buffer[rva as usize];
    let mut second_char = report.buffer[rva as usize + 1];
    while ch < 127 && b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+, -./:;<=>?@[\\]^_`{|}~ \r\n".contains(&ch) && second_char == 0{
        unicode_len += 2;
        rva += 2;
        ch = report.buffer[rva as usize];
        second_char = report.buffer[rva as usize + 1];
    }
    if ch == 0 && second_char == 0 {
        return Ok(unicode_len);
    }
    Ok(0)
}

pub fn all_zeros(bytez: &[u8]) -> Result<bool> {
    let mut res = true;
    for b in bytez {
        res &= b == &0;
    }
    Ok(res)
}

pub fn is_padding(bytez: &[u8]) -> Result<bool> {
    Ok(bytez.iter().all(|&b| b == 0x00 || b == 0xFF))
}

pub fn is_security_cookie(f: &Function, insn: &Instruction) -> Result<bool> {
    //# security cookie check should use SP or BP
    if let Some(o) = &insn.operands {
        let operands: Vec<String> = o.split(',').map(|s| s.trim().to_string()).collect();
        if !["esp", "ebp", "rsp", "rbp"].contains(&&operands[1][..]) {
            return Ok(false);
        }
        for (index, block) in f.get_blocks()?.iter().enumerate() {
            //# expect security cookie init in first basic block within first bytes (instructions)
            //        block_instructions = [i for i in block.get_instructions()?]
            if index == 0 && insn.offset < (block.1[0].offset + 0x40) {
                //}SECURITY_COOKIE_BYTES_DELTA
                return Ok(true);
            }
            //# ... or within last bytes (instructions) before a return
            if block.1[block.1.len() - 1].mnemonic.starts_with("ret")
                && insn.offset > (block.1[block.1.len() - 1].offset - 0x40)
            {
                //SECURITY_COOKIE_BYTES_DELTA
                return Ok(true);
            }
        }
    }
    Ok(false)
}

pub fn to_u16(src: &[u8]) -> Result<Vec<u16>> {
    let mut res = vec![];
    if src.len() % 2 != 0 {
        return Ok(res);
    }
    let mut i = 0;
    while i < src.len() {
        let ch = u16::from_le_bytes(src[i..i + 2].try_into()?);
        res.push(ch);
        i += 2;
    }
    Ok(res)
}

fn extract_file_strings(buf: &[u8]) -> Result<Vec<(String, u64)>> {
    let mut res = vec![];
    for (s, a) in extract_ascii_strings(buf, 4)? {
        res.push((s, a));
    }
    for (s, a) in extract_unicode_strings(buf, 4)? {
        res.push((s, a));
    }
    Ok(res)
}

const ASCII_BYTE: &str = r##" !"#$%&'()*+,-\./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]^_\x60abcdefghijklmnopqrstuvwxyz{|}\\~\t"##;
const SLICE_SIZE: usize = 4096;

lazy_static::lazy_static! {
    static ref REPEATS: Vec<u8> = vec![b'A', 0, 0xfe, 0xff];
}

pub fn extract_ascii_strings(data: &[u8], min_length: usize) -> Result<Vec<(String, u64)>> {
    if data.first().map_or(false, |&b| {
        REPEATS.contains(&b) && buf_filled_with(data, &b)
    }) {
        return Ok(vec![]);
    }
    let re = regex::bytes::Regex::new(&format!(r##"([{}]{{{},}})"##, ASCII_BYTE, min_length))?;
    Ok(re
        .find_iter(data)
        .map(|d| {
            (
                std::string::String::from_utf8_lossy(d.as_bytes()).to_string(),
                d.start() as u64,
            )
        })
        .collect())
}
pub fn extract_unicode_strings(data: &[u8], min_length: usize) -> Result<Vec<(String, u64)>> {
    if data.len() < min_length * 2 {
        return Ok(vec![]);
    }

    let mut results = Vec::new();

    // regex pattern for UTF-16LE and UTF-16BE
    let re_le = regex::bytes::Regex::new(&format!(r"((?:[\x20-\x7E]\x00){{{},}})", min_length))?;
    let re_be = regex::bytes::Regex::new(&format!(r"((?:\x00[\x20-\x7E]){{{},}})", min_length))?;
    let re_utf8 = regex::bytes::Regex::new(&format!(r"((?:[\x20-\x7E]){{{},}})", min_length))?;

    // UTF-16LE
    for mat in re_le.find_iter(data) {
        let matched_bytes = mat.as_bytes();
        let utf16_units = matched_bytes
            .chunks(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<u16>>();
        if let Ok(decoded_string) = String::from_utf16(&utf16_units) {
            results.push((decoded_string, mat.start() as u64));
        }
    }

    // UTF-16BE
    for mat in re_be.find_iter(data) {
        let matched_bytes = mat.as_bytes();
        let utf16_units = matched_bytes
            .chunks(2)
            .map(|chunk| u16::from_be_bytes([chunk[1], chunk[0]]))
            .collect::<Vec<u16>>();
        if let Ok(decoded_string) = String::from_utf16(&utf16_units) {
            results.push((decoded_string, mat.start() as u64));
        }
    }

    // UTF-8
    for mat in re_utf8.find_iter(data) {
        let matched_bytes = mat.as_bytes();
        let decoded_string = String::from_utf8_lossy(matched_bytes).to_string();
        results.push((decoded_string, mat.start() as u64));
    }

    let cleaned_results = results
        .into_iter()
        .filter(|(s, _)| !s.trim().is_empty())
        .map(|(s, pos)| (clean_string(&s), pos))
        .collect::<Vec<(String, u64)>>();

    Ok(cleaned_results)
}

fn clean_string(s: &str) -> String {
    s.replace('\u{0000}', "")
        .chars()
        .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
        .collect()
}

fn buf_filled_with(data: &[u8], character: &u8) -> bool {
    let dupe_chunk = vec![*character; SLICE_SIZE];
    let mut offset = 0;
    while offset < data.len() {
        let new_chunk = if offset + SLICE_SIZE >= data.len() {
            data[offset..].to_vec()
        } else {
            data[offset..offset + SLICE_SIZE].to_vec()
        };
        if dupe_chunk[..new_chunk.len()] != new_chunk {
            return false;
        }
        offset += SLICE_SIZE;
    }
    true
}
