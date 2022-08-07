#![allow(dead_code)]
#![allow(clippy::to_string_in_format_args)]
use crate::{
    consts::{FileFormat, Os},
    error::Error,
    Result,
};
use smda::{
    function::{Function, Instruction},
    report::DisassemblyReport,
    Disassembler,
};
use std::{collections::HashMap, convert::TryInto};

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

    fn get_blocks(&self) -> Result<HashMap<u64, Vec<Box<dyn super::Instruction>>>> {
        let mut res = HashMap::<u64, Vec<Box<dyn super::Instruction>>>::new();
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
        res.extend(self.extract_file_strings()?);
        //        res.extend(self.extract_file_function_names(pbytes)?);
        res.extend(self.extract_file_format()?);
        Ok(res)
    }

    fn get_functions(&self) -> Result<HashMap<u64, Box<dyn super::Function>>> {
        let mut res = HashMap::<u64, Box<dyn super::Function>>::new();
        for (u, f) in self.report.get_functions()? {
            res.insert(*u, Box::new(FunctionS { f: f.clone() }));
        }
        Ok(res)
    }

    fn extract_function_features(
        &self,
        f: &Box<dyn super::Function>,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        //extract function calls to
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
    ) -> Result<HashMap<u64, Vec<Box<dyn super::Instruction>>>> {
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
        Ok(res)
    }
}

impl Extractor {
    pub fn new(path: &str, high_accuracy: bool, resolve_tailcalls: bool) -> Result<Extractor> {
        Ok(Extractor {
            report: Disassembler::disassemble_file(path, high_accuracy, resolve_tailcalls)?,
            buf: Disassembler::load_file(path)?,
            path: path.to_string(),
        })
    }

    pub fn get_buf(&self) -> Result<&[u8]> {
        Ok(&self.buf)
    }

    pub fn get_elf_os(elf: &goblin::elf::Elf) -> Result<Os> {
        match elf.header.e_ident[7] {
            0x00 => Ok(Os::UNDEFINED),
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
            _ => Err(Error::UnsupportedOsError),
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

    //    pub fn extract_file_features(&self) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
    //        let mut res = vec![];
    //        //        res.extend(self.extract_file_embedded_pe()?);
    //        res.extend(self.extract_file_export_names()?);
    //        res.extend(self.extract_file_import_names()?);
    //        res.extend(self.extract_file_section_names()?);
    //        res.extend(self.extract_file_strings()?);
    //        //        res.extend(self.extract_file_function_names(pbytes)?);
    //        res.extend(self.extract_file_format()?);
    //        Ok(res)
    //    }

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

    fn _extract_file_embedded_pe(&self) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        for (offset, _) in Extractor::carve_pe(&self.report.buffer, 1)? {
            res.push((
                crate::rules::features::Feature::Characteristic(
                    crate::rules::features::CharacteristicFeature::new("embedded pe", "")?,
                ),
                offset,
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
                *b as u64,
            ));
        }
        Ok(res)
    }

    pub fn extract_file_export_names(&self) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        for (e, o) in &self.report.exports {
            res.push((
                crate::rules::features::Feature::Export(
                    crate::rules::features::ExportFeature::new(e, "")?,
                ),
                *o as u64,
            ));
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
            res.push((
                crate::rules::features::Feature::String(
                    crate::rules::features::StringFeature::new(&s, "")?,
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
                if !operand.contains("ptr") {
                    continue;
                }
                //NOTE not sure
                if
                /*operand.contains("esp") ||*/
                operand.contains("ebp") || operand.contains("rbp") {
                    continue;
                }
                let mut number = 0;
                let re_number_hex =
                    regex::Regex::new(r"(?P<sign>[+\-]) (?P<num>0x[a-fA-F0-9]+)").unwrap();
                let re_number_int = regex::Regex::new(r"(?P<sign>[+\-]) (?P<num>[0-9])").unwrap();
                let number_hex = re_number_hex.captures(operand);
                let number_int = re_number_int.captures(operand);
                if let Some(n) = number_hex {
                    number = i128::from_str_radix(&n["num"][2..], 16)?;
                    if &n["num"] == "-" {
                        number *= -1;
                    }
                } else if let Some(n) = number_int {
                    number = (&n["num"]).parse::<i128>()?;
                    if &n["num"] == "-" {
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
                res.push((
                    crate::rules::features::Feature::String(
                        crate::rules::features::StringFeature::new(
                            string_read.trim_end_matches('\x00'),
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
                if all_zeros(bytes_read)? {
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

    pub fn extract_insn_number_features(
        &self,
        f: &Function,
        insn: &Instruction,
    ) -> Result<Vec<(crate::rules::features::Feature, u64)>> {
        let mut res = vec![];
        //# example:
        //#
        //#     push    3136B0h         ; dwControlCode
        if let Some(o) = &insn.operands {
            let operands: Vec<String> = o.split(',').map(|s| s.trim().to_string()).collect();
            if insn.mnemonic == "add"
                && ["esp".to_string(), "rsp".to_string()].contains(&operands[0])
            {
                //# skip things like:
                //#
                //#    .text:00401140                 call    sub_407E2B
                //#    .text:00401145                 add     esp, 0Ch
                return Ok(vec![]);
            }
            for (i, operand) in operands.iter().enumerate() {
                if let Some(x) = operand.strip_prefix("0x") {
                    if let Ok(s) = i128::from_str_radix(x, 16) {
                        res.push((
                            crate::rules::features::Feature::Number(
                                crate::rules::features::NumberFeature::new(f.bitness, &s, "")?,
                            ),
                            insn.offset,
                        ));
                        res.push((
                            crate::rules::features::Feature::OperandNumber(
                                crate::rules::features::OperandNumberFeature::new(&i, &s, "")?,
                            ),
                            insn.offset,
                        ));
                    }
                } else if operand.ends_with('h') {
                    if let Ok(s) = i128::from_str_radix(&operand[..operand.len() - 1], 16) {
                        res.push((
                            crate::rules::features::Feature::Number(
                                crate::rules::features::NumberFeature::new(f.bitness, &s, "")?,
                            ),
                            insn.offset,
                        ));
                        res.push((
                            crate::rules::features::Feature::OperandNumber(
                                crate::rules::features::OperandNumberFeature::new(&i, &s, "")?,
                            ),
                            insn.offset,
                        ));
                    }
                } else if let Ok(s) = i128::from_str_radix(operand, 16) {
                    res.push((
                        crate::rules::features::Feature::Number(
                            crate::rules::features::NumberFeature::new(f.bitness, &s, "")?,
                        ),
                        insn.offset,
                    ));
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
        if f.apirefs.contains_key(&insn.offset) {
            let (dll, api) = &f.apirefs[&insn.offset];
            for name in generate_symbols(dll, api)? {
                res.push((
                    crate::rules::features::Feature::Api(crate::rules::features::ApiFeature::new(
                        &name, "",
                    )?),
                    insn.offset,
                ));
            }
        } else if f.outrefs.contains_key(&insn.offset) {
            let mut current_function = f;
            let mut current_instruction = insn;
            for _index in 0..5 {
                //}THUNK_CHAIN_DEPTH_DELTA
                if current_function.outrefs[&current_instruction.offset].len() == 1 {
                    let target = current_function.outrefs[&current_instruction.offset][0];
                    if let Ok(referenced_function) = self.report.get_function(target) {
                        //# TODO SMDA: implement this function for both jmp and call, checking if function has 1 instruction which refs an API
                        if referenced_function.is_api_thunk()? {
                            if referenced_function.apirefs.contains_key(&target) {
                                let (dll, api) = &referenced_function.apirefs[&target];
                                for name in generate_symbols(dll, api)? {
                                    res.push((
                                        crate::rules::features::Feature::Api(
                                            crate::rules::features::ApiFeature::new(&name, "")?,
                                        ),
                                        insn.offset,
                                    ));
                                }
                            }
                        } else if referenced_function.get_num_instructions()? == 1
                            && referenced_function.get_num_outrefs()? == 1
                        {
                            current_function = referenced_function;
                            current_instruction = referenced_function.get_instructions()?[0];
                        }
                    } else {
                        return Ok(res);
                    }
                }
            }
        }
        Ok(res)
    }

    fn xor_static(data: &[u8], i: u8) -> Result<Vec<u8>> {
        let mut res = vec![];
        for c in data {
            res.push(c ^ i);
        }
        Ok(res)
    }

    fn carve_pe(pbytes: &[u8], offset: u64) -> Result<Vec<(u64, u64)>> {
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
        for (mzx, pex, key) in mz_xor {
            if let Some(ff) = pbytes[offset as usize..]
                .windows(mzx.len())
                .position(|window| window == mzx)
            {
                todo.push((ff, mzx, pex, key));
            }
        }
        let mut res = vec![];
        while !todo.is_empty() {
            // println!("{}", todo.len());
            let (off, mzx, pex, key) = todo.pop().unwrap();
            //The MZ header has one field we will check
            //e_lfanew is at 0x3c
            let e_lfanew = off + 0x3C;
            if pblen < (e_lfanew + 4) {
                continue;
            }

            let ppp: [u8; 4] = Extractor::xor_static(&pbytes[e_lfanew..e_lfanew + 4], key)?
                .try_into()
                .map_err(|_| Error::InvalidRule(line!(), "aaa".to_string()))?;
            let newoff = u32::from_le_bytes(ppp);
            if let Some(ff) = pbytes[off + 1..]
                .windows(mzx.len())
                .position(|window| window == mzx)
            {
                todo.push((ff, mzx, pex.clone(), key));
            }
            let peoff = off + newoff as usize;
            if pblen < (peoff + 2) {
                continue;
            }
            if pbytes[peoff..peoff + 2] == pex {
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

pub fn generate_symbols(dll: &Option<String>, symbol: &Option<String>) -> Result<Vec<String>> {
    let mut res = vec![];
    let mut dll_name = dll
        .clone()
        .ok_or_else(|| Error::InvalidRule(line!(), file!().to_string()))?;
    if dll_name.ends_with(".dll") {
        dll_name = dll_name[..dll_name.len() - 4].to_string();
    }
    let symbol_name = symbol
        .clone()
        .ok_or_else(|| Error::InvalidRule(line!(), file!().to_string()))?;
    res.push(format!("{}.{}", dll_name, symbol_name));

    if &symbol_name[..1] != "#" {
        res.push(symbol_name.clone());
    }

    //TODO
    if symbol_name.ends_with('A') || symbol_name.ends_with('W') {
        res.push(format!(
            "{}.{}",
            dll_name,
            symbol_name[..symbol_name.len() - 1].to_string()
        ));
        if &symbol_name[..1] != "#" {
            res.push(symbol_name[..symbol_name.len() - 1].to_string());
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
    va: &u64,
    num_bytes: usize,
) -> Result<&'a [u8]> {
    let rva = va - report.base_addr;
    let buffer_end = report.buffer.len();
    if rva + num_bytes as u64 > buffer_end as u64 {
        Ok(&report.buffer[rva as usize..])
    } else {
        Ok(&report.buffer[rva as usize..rva as usize + num_bytes])
    }
}

pub fn read_string(report: &DisassemblyReport, offset: &u64) -> Result<String> {
    let alen = detect_ascii_len(report, offset)?;
    if alen > 1 {
        return Ok(std::str::from_utf8(read_bytes(report, offset, alen)?)?.to_string());
    }
    let ulen = detect_unicode_len(report, offset)?;
    if ulen > 2 {
        let bb: &[u16] = &to_u16(read_bytes(report, offset, ulen)?)?;
        return Ok(std::string::String::from_utf16(bb)?);
    }
    Ok("".to_string())
}

pub fn detect_ascii_len(report: &DisassemblyReport, offset: &u64) -> Result<usize> {
    let mut ascii_len = 0;
    let mut rva = offset - report.base_addr;
    let mut ch = report.buffer[rva as usize];
    while ch < 127 && b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+, -./:;<=>?@[\\]^_`{|}~ ".contains(&ch){
        ascii_len += 1;
        rva += 1;
        ch = report.buffer[rva as usize];
    }
    if ch == 0 {
        return Ok(ascii_len);
    }
    Ok(0)
}

pub fn detect_unicode_len(report: &DisassemblyReport, offset: &u64) -> Result<usize> {
    let mut unicode_len = 0;
    let mut rva = offset - report.base_addr;
    let mut ch = report.buffer[rva as usize];
    let mut second_char = report.buffer[rva as usize + 1];
    while ch < 127 && b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+, -./:;<=>?@[\\]^_`{|}~ ".contains(&ch) && second_char == 0{
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
    if REPEATS.contains(&data[0]) && buf_filled_with(data, &data[0]) {
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
    if REPEATS.contains(&data[0]) && buf_filled_with(data, &data[0]) {
        return Ok(vec![]);
    }
    let re = regex::bytes::Regex::new(&format!(
        r##"((?:[{}]\x00){{{},}})"##,
        ASCII_BYTE, min_length
    ))?;
    Ok(re
        .find_iter(data)
        .map(|d| {
            let dd = (0..(d.end() + 1 - d.start()) / 2)
                .map(|i| u16::from_be_bytes([d.as_bytes()[2 * i], d.as_bytes()[2 * i + 1]]))
                .collect::<Vec<u16>>();
            (
                std::string::String::from_utf16_lossy(&dd).to_string(),
                d.start() as u64,
            )
        })
        .collect())
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
