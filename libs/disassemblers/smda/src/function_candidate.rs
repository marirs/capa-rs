use crate::{BinaryInfo, Result};
use std::{
    collections::{HashMap, HashSet},
    convert::TryInto,
};

#[derive(Debug, Clone)]
struct CommonPlagues {
    cp: HashMap<u32, HashMap<u32, HashMap<Vec<u8>, u32>>>,
}

impl CommonPlagues {
    pub fn init() -> CommonPlagues {
        CommonPlagues {
            cp: hashmap! {
                5 => hashmap!{
                    32 => hashmap!{
                        b"\x8B\xFF\x55\x8B\xEC".to_vec() => 50, //mov edi, edi, push ebp, mov ebp, esp
                        b"\x89\xFF\x55\x8B\xEC".to_vec() => 50, //mov edi, edi, push ebp, mov ebp, esp
                    },
                    64 => hashmap!{}
                },
                3 => hashmap!{
                    32 => hashmap!{
                        b"\x55\x8B\xEC".to_vec() => 50,  // push ebp, mov ebp, esp
                    },
                    64 => hashmap!{}
                },
                1 => hashmap!{
                    32 => hashmap!{
                        b"\x55".to_vec() => 51,  //311150 (51.09%) -- cumulative =>   51.09%
                        b"\x8b".to_vec() =>  10,  //  62878 (10.32%) -- cumulative =>   61.41%
                        b"\x83".to_vec() =>  7,  //  46477 (7.63%) -- cumulative =>   69.05%
                        b"\x53".to_vec() =>  6,  //  38773 (6.37%) -- cumulative =>   75.41%
                        b"\x57".to_vec() =>  5,  //  36048 (5.92%) -- cumulative =>   81.33%
                        b"\x56".to_vec() =>  5,  //  31955 (5.25%) -- cumulative =>   86.58%
                        b"\xff".to_vec() =>  4,  //  24444 (4.01%) -- cumulative =>   90.59%
                        b"\xe9".to_vec() =>  2,  //  16420 (2.70%) -- cumulative =>   93.29%
                        b"\xb8".to_vec() =>  1,  //   6577 (1.08%) -- cumulative =>   94.37%
                        b"\xc3".to_vec() =>  1,  //   5638 (0.93%) -- cumulative =>   95.29%
                        b"\xa1".to_vec() =>  1,  //   4168 (0.68%) -- cumulative =>   95.98%
                        b"\x6a".to_vec() =>  1,  //   3815 (0.63%) -- cumulative =>   96.60%
                        b"\x51".to_vec() =>  1,  //   2753 (0.45%) -- cumulative =>   97.06%
                        b"\x31".to_vec() =>  1,  //   2514 (0.41%) -- cumulative =>   97.47%
                        b"\xf3".to_vec() =>  1,  //   2109 (0.35%) -- cumulative =>   97.82%
                        b"\x33".to_vec() =>  1,  //   1279 (0.21%) -- cumulative =>   98.03%
                        b"\x81".to_vec() =>  1,  //   1261 (0.21%) -- cumulative =>   98.23%
                        b"\x85".to_vec() =>  1,  //   1045 (0.17%) -- cumulative =>   98.40%
                        b"\xe8".to_vec() =>  1,  //   1005 (0.17%) -- cumulative =>   98.57%
                        b"\x8d".to_vec() =>  1,  //    896 (0.15%) -- cumulative =>   98.72%
                        b"\x68".to_vec() =>  1,  //    749 (0.12%) -- cumulative =>   98.84%
                        b"\x80".to_vec() =>  1,  //    703 (0.12%) -- cumulative =>   98.95%
                    },
                    64 =>  hashmap!{
                        b"\x55".to_vec() =>  33,  // 196922 (33.40%) -- cumulative =>   33.40%
                        b"\x48".to_vec() =>  21,  // 124360 (21.09%) -- cumulative =>   54.49%
                        b"\x41".to_vec() =>  15,  //  91785 (15.57%) -- cumulative =>   70.06%
                        b"\x53".to_vec() =>  6,  //  37559 (6.37%) -- cumulative =>   76.43%
                        b"\xff".to_vec() =>  3,  //  22877 (3.88%) -- cumulative =>   80.31%
                        b"\x40".to_vec() =>  3,  //  18018 (3.06%) -- cumulative =>   83.36%
                        b"\xe9".to_vec() =>  2,  //  15434 (2.62%) -- cumulative =>   85.98%
                        b"\x50".to_vec() =>  1,  //  11713 (1.99%) -- cumulative =>   87.97%
                        b"\x8b".to_vec() =>  1,  //   9130 (1.55%) -- cumulative =>   89.52%
                        b"\x4c".to_vec() =>  1,  //   6737 (1.14%) -- cumulative =>   90.66%
                        b"\xc3".to_vec() =>  1,  //   5978 (1.01%) -- cumulative =>   91.67%
                        b"\x89".to_vec() =>  1,  //   5852 (0.99%) -- cumulative =>   92.66%
                        b"\xb8".to_vec() =>  1,  //   5073 (0.86%) -- cumulative =>   93.52%
                        b"\x31".to_vec() =>  1,  //   4902 (0.83%) -- cumulative =>   94.36%
                        b"\x44".to_vec() =>  1,  //   4504 (0.76%) -- cumulative =>   95.12%
                        b"\x0f".to_vec() =>  1,  //   3196 (0.54%) -- cumulative =>   95.66%
                        b"\x83".to_vec() =>  1,  //   3120 (0.53%) -- cumulative =>   96.19%
                        b"\xf3".to_vec() =>  1,  //   2363 (0.40%) -- cumulative =>   96.59%
                        b"\xf2".to_vec() =>  1,  //   2349 (0.40%) -- cumulative =>   96.99%
                        b"\x85".to_vec() =>  1,  //   1806 (0.31%) -- cumulative =>   97.30%
                        b"\x33".to_vec() =>  1,  //   1605 (0.27%) -- cumulative =>   97.57%
                        b"\x66".to_vec() =>  1,  //   1370 (0.23%) -- cumulative =>   97.80%
                        b"\xba".to_vec() =>  1,  //   1235 (0.21%) -- cumulative =>   98.01%
                        b"\x45".to_vec() =>  1,  //   1227 (0.21%) -- cumulative =>   98.22%
                        b"\x80".to_vec() =>  1,  //   1197 (0.20%) -- cumulative =>   98.42%
                        b"\xc7".to_vec() =>  1,  //   1034 (0.18%) -- cumulative =>   98.60%
                        b"\xb0".to_vec() =>  1,  //    911 (0.15%) -- cumulative =>   98.75%
                        b"\xbf".to_vec() =>  1,  //    894 (0.15%) -- cumulative =>   98.90%
                    }
                }
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct FunctionCandidate {
    cp: CommonPlagues,
    bitness: u32,
    pub addr: u64,
    rel_start_addr: u64,
    bytes: [u8; 5],
    lang_spec: Option<String>,
    pub call_ref_sources: HashSet<u64>,
    finished: bool,
    is_symbol: bool,
    is_gap_candidate: bool,
    is_tailcall: bool,
    pub alignment: u64,
    pub analysis_aborted: bool,
    abortion_reason: String,
    score: f32,
    tfidf_score: f32,
    confidence: f32,
    function_start_score: f32,
    is_stub: bool,
    is_initial_candidate: bool,
    is_exception_handler: bool,
}

impl FunctionCandidate {
    pub fn new(bi: &BinaryInfo, addr: u64) -> Result<FunctionCandidate> {
        let rel_addr = addr - bi.base_addr as u64;
        let mut fc = FunctionCandidate {
            cp: CommonPlagues::init(),
            bitness: bi.bitness,
            addr,
            rel_start_addr: rel_addr,
            bytes: bi.binary[rel_addr as usize..(rel_addr + 5) as usize].try_into()?,
            lang_spec: None,
            call_ref_sources: HashSet::new(),
            finished: false,
            is_symbol: false,
            is_gap_candidate: false,
            is_tailcall: false,
            alignment: 0,
            analysis_aborted: false,
            abortion_reason: String::from(""),
            score: 0.0,
            tfidf_score: 0.0,
            confidence: 0.0,
            function_start_score: 0.0,
            is_stub: false,
            is_initial_candidate: false,
            is_exception_handler: false,
        };
        if fc.addr % 4 == 0 {
            fc.alignment = 4;
        }
        if fc.addr % 16 == 0 {
            fc.alignment = 16;
        }
        Ok(fc)
    }

    pub fn add_call_ref(&mut self, source_ref: u64) -> Result<()> {
        if !self.call_ref_sources.contains(&source_ref) {
            self.call_ref_sources.insert(source_ref);
        }
        self.score = 0.0;
        Ok(())
    }

    pub fn set_initial_candidate(&mut self) {
        self.is_initial_candidate = true;
    }

    pub fn set_is_stub(&mut self) {
        self.is_stub = true;
        self.score = 0.0;
    }

    pub fn set_is_exception_handler(&mut self) {
        self.is_exception_handler = true;
        self.score = 0.0;
    }

    pub fn set_is_gap_candidate(&mut self, flag: bool) -> Result<()> {
        self.is_gap_candidate = flag;
        Ok(())
    }

    pub fn set_analysis_aborted(&mut self, reason: &str) -> Result<()> {
        self.finished = true;
        self.analysis_aborted = true;
        self.abortion_reason = reason.to_string();
        Ok(())
    }

    pub fn set_analysis_completed(&mut self) -> Result<()> {
        self.finished = true;
        Ok(())
    }

    pub fn remove_call_refs(&mut self, source_addrs: Vec<u64>) -> Result<()> {
        for addr in source_addrs {
            if self.call_ref_sources.contains(&addr) {
                self.call_ref_sources.remove(&addr);
            }
        }
        self.score = 0.0;
        Ok(())
    }

    pub fn set_tfidf(&mut self, tfidf_score: f32) -> Result<()> {
        self.tfidf_score = tfidf_score;
        Ok(())
    }

    pub fn init_confidence(&mut self) -> Result<f32> {
        if self.confidence == 0.0 {
            //# based on evaluation over Andriesse, Bao, and Plohmann data sets
            let mut weighted_confidence = 0.298
                * if self.has_common_function_start()? {
                    1.0
                } else {
                    0.0
                };
            weighted_confidence += 0.321 * if self.tfidf_score < 0.0 { 1.0 } else { 0.0 }
                + 0.124 * if self.tfidf_score < -2.0 { 1.0 } else { 0.0 }
                + 0.120 * if self.tfidf_score < -4.0 { 1.0 } else { 0.0 }
                + 0.101 * if self.tfidf_score < -1.0 { 1.0 } else { 0.0 }
                + 0.025 * if self.tfidf_score < -8.0 { 1.0 } else { 0.0 };
            //# above experiments show that multiple inbound call references are basically always indeed functions
            if self.call_ref_sources.len() > 1 {
                self.confidence = 1.0;
            }
            //# initially recognized candidates are also almost always functions as they follow this heuristic
            else if self.is_initial_candidate {
                self.confidence = 0.5 + 0.5 * weighted_confidence;
            } else {
                self.confidence = weighted_confidence;
            }
        }
        Ok(self.confidence)
    }

    pub fn get_confidence(&self) -> Result<f32> {
        Ok(self.confidence)
    }

    pub fn has_common_function_start(&self) -> Result<bool> {
        for length in self.cp.cp.keys() {
            let byte_sequence = &self.bytes[..*length as usize];
            if self.cp.cp[length][&self.bitness].contains_key(byte_sequence) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn set_is_tailcall_candidate(&mut self, flag: bool) -> Result<()> {
        self.is_tailcall = flag;
        Ok(())
    }

    pub fn set_is_symbol(&mut self, flag: bool) -> Result<()> {
        self.is_symbol = flag;
        Ok(())
    }

    pub fn get_characteristics(&self) -> Result<String> {
        Ok(format!(
            "{}{}{}{}{}{}{}{}{}{}{}",
            if self.is_initial_candidate { "i" } else { "-" },
            if self.is_symbol { "s" } else { "-" },
            if self.is_stub { "u" } else { "-" },
            if self.alignment != 0 { "a" } else { "-" },
            if self.lang_spec.is_some() {
                "l"
            } else {
                "-"
            },
            if self.has_common_function_start()? {
                "p"
            } else {
                "-"
            },
            if !self.call_ref_sources.is_empty() {
                "r"
            } else {
                "-"
            },
            if self.is_tailcall { "t" } else { "-" },
            if self.is_gap_candidate { "g" } else { "-" },
            if self.finished { "f" } else { "-" },
            if self.analysis_aborted { "x" } else { "-" }
        ))
    }

    pub fn get_tfidf(&self) -> Result<f32> {
        Ok(self.tfidf_score)
    }
}
