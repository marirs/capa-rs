use crate::error::Error;
use crate::result::Result;

#[derive(Debug)]
pub struct TailCall {
    source_addr: u64,
    destination_addr: u64,
    destination_function: u64,
}

#[derive(Debug)]
pub struct TailCallAnalyser {
    jumps: std::collections::HashMap<u64, Vec<u64>>,
    tmp_jumps: std::collections::HashMap<u64, Vec<u64>>,
    functions: std::collections::HashMap<u64, crate::disassembler::FunctionAnalysisState>,
}

impl TailCallAnalyser {
    pub fn new() -> TailCallAnalyser {
        TailCallAnalyser {
            jumps: std::collections::HashMap::new(),
            tmp_jumps: std::collections::HashMap::new(),
            functions: std::collections::HashMap::new(),
        }
    }

    pub fn init(&mut self) -> Result<()> {
        self.tmp_jumps = std::collections::HashMap::new();
        Ok(())
    }

    pub fn add_jump(&mut self, source: u64, destination: u64) -> Result<()> {
        if let Some(s) = self.tmp_jumps.get_mut(&source) {
            s.push(destination);
        } else {
            self.tmp_jumps.insert(source, vec![destination]);
        }
        Ok(())
    }

    pub fn finalize_function(
        &mut self,
        _function_state: &crate::disassembler::FunctionAnalysisState,
    ) -> Result<()> {
        for (source, destinations) in &self.tmp_jumps {
            self.jumps.insert(*source, destinations.to_vec());
        }
        self.tmp_jumps.clear();
        //TODO        self.functions.push(function_state);
        Ok(())
    }

    pub fn resolve_tailcalls(
        disassembler: &mut crate::disassembler::Disassembler,
        state: &mut crate::disassembler::FunctionAnalysisState,
    ) -> Result<std::collections::HashSet<u64>> {
        let mut newly_created_functions = std::collections::HashSet::new();
        for tailcall in disassembler.tailcall_analyzer.get_tailcalls()? {
            //# remove the information from the function-analysis state of the disassembly
            match disassembler
                .tailcall_analyzer
                .get_function_by_start_addr(tailcall.destination_function)
            {
                Ok(f) => {
                    if disassembler.tailcall_analyzer.functions[&f].is_tailcall_function {
                        disassembler.analyse_function(tailcall.destination_function, false)?;
                        continue;
                    }
                    disassembler
                        .tailcall_analyzer
                        .functions
                        .remove(&f)
                        .ok_or(Error::LogicError(file!(), line!()))?;
                    state.revert_analysis()?;
                }
                _ => {
                    disassembler.analyse_function(tailcall.destination_function, false)?;
                    continue;
                }
            }
            //# analyze the tailcall destination as function
            disassembler.analyse_function(tailcall.destination_addr, false)?;
            newly_created_functions.insert(tailcall.destination_addr);
            if let Ok(addr) = disassembler
                .tailcall_analyzer
                .get_function_by_start_addr(tailcall.destination_addr)
            {
                if disassembler.tailcall_analyzer.functions[&addr]
                    .instruction_start_bytes
                    .contains(&tailcall.destination_function)
                {
                    //# analyze the (previously) broken function a second time
                    disassembler.analyse_function(tailcall.destination_function, false)?;
                    let addr_function = disassembler
                        .tailcall_analyzer
                        .get_function_by_start_addr(tailcall.destination_function)?;
                    disassembler
                        .tailcall_analyzer
                        .functions
                        .get_mut(&addr_function)
                        .ok_or(Error::LogicError(file!(), line!()))?
                        .is_tailcall_function = true;
                }
            }
        }
        Ok(newly_created_functions)
    }

    pub fn get_tailcalls(&self) -> Result<Vec<TailCall>> {
        let mut result = vec![];
        //# jumps sorted by (destination, source)
        let mut jumps = std::collections::HashSet::new();
        let mut jumps_dest = std::collections::HashSet::new();
        for (s, ds) in &self.jumps {
            for d in ds {
                jumps.insert((*s, *d));
                jumps_dest.insert(*d);
            }
        }
        //# for each function generate the intervals that contain the instructions
        for (_, function) in &self.functions {
            //# check if there are any jumps from outside the function to inside the function
            let function_intervals = self.get_function_intervals(&function);
            if let Err(_) = function_intervals {
                //# empty function?
                continue;
            }
            let function_intervals = function_intervals.as_ref().unwrap();
            let mut min_addr = 0xFFFFFFFFFFFFFFFF;
            let mut max_addr = 0;
            for interval in function_intervals {
                if min_addr > interval.0 {
                    min_addr = interval.0;
                }
                if max_addr < interval.1 {
                    max_addr = interval.1;
                }
            }
            for (source, destination) in &jumps {
                // //}[bisect.bisect_left(jumps_dest,
                // min_addr):bisect.bisect_right(jumps_dest,
                // max_addr)]:
                let mut flag1 = false;
                let mut flag2 = true;
                for (first, last) in function_intervals {
                    if first <= destination && destination <= &last {
                        flag1 |= true;
                    }
                    if !(source < first || source > last) {
                        flag2 &= false;
                    }
                }
                if
                //the jumps destination is different from the functions start address
                destination != &function.start_addr &&
                    //the jumps destination is in one of the functions intervals
                    flag1 &&
                //# the jump originates from outside the function (outside all intervals)
                    flag2
                {
                    result.push(TailCall {
                        source_addr: *source,
                        destination_addr: *destination,
                        destination_function: function.start_addr,
                    });
                }
            }
        }
        Ok(result)
    }

    fn get_function_by_start_addr(&self, start_addr: u64) -> Result<u64> {
        for (_, function) in &self.functions {
            if function.start_addr == start_addr {
                return Ok(function.start_addr);
            }
        }
        Err(Error::LogicError(file!(), line!()))
    }

    fn get_function_intervals(
        &self,
        function_state: &crate::disassembler::FunctionAnalysisState,
    ) -> Result<Vec<(u64, u64)>> {
        let mut intervals = vec![];
        let instructions = &function_state.instructions;
        if instructions.len() == 0 {
            return Err(Error::LogicError(file!(), line!()));
        }
        let mut first_instruction = &instructions[0];
        let mut last_instruction = first_instruction;
        for instruction in instructions {
            if instruction.0 > last_instruction.0 + last_instruction.1 as u64 {
                intervals.push((first_instruction.0, last_instruction.0));
                first_instruction = instruction
            }
            last_instruction = instruction
        }
        intervals.push((first_instruction.0, last_instruction.0));
        Ok(intervals)
    }
}
