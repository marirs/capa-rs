use crate::result::Result;

#[derive(Debug)]
pub struct DisassemblyStatistics {
    num_functions: usize,
    num_recursive_functions: usize,
    num_leaf_functions: usize,
    num_basic_blocks: usize,
    num_instructions: usize,
    num_api_calls: usize,
    num_function_calls: usize,
    num_failed_functions: usize,
}

impl DisassemblyStatistics {
    pub fn new(
        disassembly_result: &mut crate::disassembler::DisassemblyResult,
    ) -> Result<DisassemblyStatistics> {
        Ok(DisassemblyStatistics {
            num_functions: disassembly_result.functions.len(),
            num_recursive_functions: disassembly_result.recursive_functions.len(),
            num_leaf_functions: disassembly_result.leaf_functions.len(),
            num_basic_blocks: DisassemblyStatistics::count_blocks(disassembly_result)?,
            num_instructions: DisassemblyStatistics::count_instructions(disassembly_result)?,
            num_api_calls: DisassemblyStatistics::count_api_calls(disassembly_result)?,
            num_function_calls: DisassemblyStatistics::count_function_calls(disassembly_result)?,
            num_failed_functions: disassembly_result.failed_analysis_addr.len(),
        })
    }

    fn count_blocks(disassembly_result: &crate::disassembler::DisassemblyResult) -> Result<usize> {
        let mut num_blocks = 0;
        for (_, blocks) in &disassembly_result.functions {
            num_blocks += blocks.len();
        }
        Ok(num_blocks)
    }

    fn count_api_calls(
        disassembly_result: &mut crate::disassembler::DisassemblyResult,
    ) -> Result<usize> {
        Ok(disassembly_result.get_all_api_refs()?.len())
    }

    fn count_instructions(
        disassembly_result: &crate::disassembler::DisassemblyResult,
    ) -> Result<usize> {
        let mut num_ins = 0;
        for (function_offset, _) in &disassembly_result.functions {
            for block in &disassembly_result.functions[&function_offset] {
                num_ins += block.len();
            }
        }
        Ok(num_ins)
    }

    fn count_function_calls(
        disassembly_result: &crate::disassembler::DisassemblyResult,
    ) -> Result<usize> {
        let mut num_calls = 0;
        for (function_start, _) in &disassembly_result.functions {
            if disassembly_result
                .code_refs_to
                .contains_key(&function_start)
            {
                num_calls += disassembly_result.code_refs_to[&function_start].len();
            }
        }
        Ok(num_calls)
    }
}
