use crate::{error::Error, Result};
use std::collections::HashMap;

#[derive(Debug)]
pub struct MnemonicTfIdf {
    bitness: u32,
    idf: HashMap<&'static str, f32>,
}

impl MnemonicTfIdf {
    pub fn new() -> MnemonicTfIdf {
        MnemonicTfIdf {
            bitness: 0,
            idf: HashMap::new(),
        }
    }

    pub fn init(&mut self, bitness: u32) -> Result<()> {
        let mut counts = match bitness {
            32 => {
                maplit::hashmap! {"num_functions"=> 129538, "ret"=> 107683, "mov"=> 106382, "push"=> 101507, "pop"=> 93246, "call"=> 90833, "add"=> 75808, "jmp"=> 70397, "cmp"=> 70245, "je"=> 64126, "jne"=> 60986, "test"=> 58090, "xor"=> 56252, "lea"=> 50181, "sub"=> 48433, "inc"=> 29640, "and"=> 28883, "or"=> 19398, "movzx"=> 18699, "jle"=> 16280, "dec"=> 15928, "jl"=> 14663, "leave"=> 12343, "jge"=> 11945, "jg"=> 9261, "jb"=> 9202, "shl"=> 8954, "sbb"=> 8001, "ja"=> 7944, "neg"=> 7654, "jae"=> 6880, "jbe"=> 6870, "shr"=> 6600, "sar"=> 5880, "movsx"=> 5462, "js"=> 5252, "imul"=> 5098, "jns"=> 5082, "setne"=> 4494, "cdq"=> 4281, "sete"=> 4021, "nop"=> 3381, "rep movsd"=> 1839, "not"=> 1664, "idiv"=> 1515, "int3"=> 1502, "adc"=> 1325, "div"=> 1179, "rep stosd"=> 838, "rep movsb"=> 771, "fstp"=> 755, "setg"=> 713, "fld"=> 667, "setl"=> 496, "mul"=> 474, "setge"=> 450, "movsd"=> 430, "fldz"=> 413, "setle"=> 401, "stmxcsr"=> 367, "fnstsw"=> 365, "stosd"=> 360, "rol"=> 332, "fnstcw"=> 321, "fild"=> 303, "xchg"=> 280, "wait"=> 271, "shld"=> 241, "cld"=> 239, "cmove"=> 234, "cmovne"=> 223, "ror"=> 201, "rep stosb"=> 200, "rcr"=> 193, "xorps"=> 186, "movdqu"=> 184, "jp"=> 173, "shrd"=> 172, "movq"=> 171, "movlpd"=> 168, "repne scasb"=> 156, "movsb"=> 153, "movsw"=> 148, "fst"=> 148, "pushfd"=> 141, "fldcw"=> 141, "std"=> 139, "movdqa"=> 139, "sets"=> 130, "setns"=> 129, "bts"=> 118, "clc"=> 118, "bt"=> 114, "fadd"=> 108, "fcomp"=> 106, "fucompp"=> 105, "stosb"=> 100, "pxor"=> 100, "cwde"=> 98, "ldmxcsr"=> 96, "stosw"=> 93, "lock xadd"=> 91, "fnclex"=> 77, "cmova"=> 70, "fmul"=> 69, "jnp"=> 64, "fchs"=> 63, "loop"=> 63, "fld1"=> 63, "popal"=> 61, "fistp"=> 61, "cmovb"=> 61, "pushal"=> 56, "movd"=> 52, "fxch"=> 44, "lodsb"=> 41, "fdiv"=> 37, "fmulp"=> 36, "fsub"=> 33, "paddd"=> 33, "ljmp"=> 31, "fdivp"=> 30, "xorpd"=> 29, "cpuid"=> 28, "lock cmpxchg"=> 28, "lodsd"=> 27, "cmovae"=> 27, "setb"=> 26, "fdivrp"=> 26, "int"=> 26, "fldpi"=> 25, "psubd"=> 24, "fsubp"=> 22, "retf"=> 22, "cvttsd2si"=> 21, "faddp"=> 20, "movapd"=> 19, "frndint"=> 19, "fucomp"=> 19, "psrldq"=> 19, "fabs"=> 19, "psrlq"=> 18, "psllq"=> 18, "cmovl"=> 18, "fcom"=> 18, "fcompp"=> 18, "repe cmpsb"=> 17, "cmovbe"=> 17, "andpd"=> 17, "ucomisd"=> 17, "bswap"=> 17, "jecxz"=> 16, "cmovns"=> 16, "pshufd"=> 16, "popfd"=> 14, "cmovg"=> 14, "xlatb"=> 14, "fsubr"=> 14, "seto"=> 13, "cbw"=> 12, "fxam"=> 12, "rdtsc"=> 11, "cmovge"=> 11, "cmovs"=> 11, "pslld"=> 11, "fdivr"=> 10, "addsd"=> 10, "repe cmpsd"=> 9, "cmpnlepd"=> 9, "psrld"=> 9, "subsd"=> 9, "pand"=> 8, "cmpltpd"=> 8, "orpd"=> 8, "f2xm1"=> 8, "fscale"=> 8, "lodsw"=> 7, "cmovle"=> 6, "hlt"=> 6, "insb"=> 6, "outsb"=> 6, "fidiv"=> 6, "pmulld"=> 6, "in"=> 5, "repne scasw"=> 5, "lcall"=> 5, "das"=> 5, "outsd"=> 5, "fninit"=> 4, "seta"=> 4, "punpckldq"=> 4, "arpl"=> 3, "rcl"=> 3, "loopne"=> 3, "comisd"=> 3, "lock inc"=> 2, "lock dec"=> 2, "btr"=> 2, "sahf"=> 2, "sti"=> 2, "lock xchg"=> 2, "pshufb"=> 2, "outsw"=> 2, "aas"=> 2, "aaa"=> 2, "jo"=> 2, "xcryptcbc"=> 2, "cvtsi2sd"=> 2, "repne scasd"=> 2, "bound"=> 2, "cmpsd"=> 2, "sal"=> 1, "fisttp"=> 1, "fcomip"=> 1, "fucomip"=> 1, "lahf"=> 1, "pushf"=> 1, "scasb"=> 1, "cli"=> 1, "jcxz"=> 1, "repe cmpsw"=> 1, "emms"=> 1, "por"=> 1, "setae"=> 1, "pslldq"=> 1, "aeskeygenassist"=> 1, "aesenc"=> 1, "aesenclast"=> 1, "paddq"=> 1, "pcmpeqq"=> 1, "punpcklqdq"=> 1, "psubq"=> 1, "aam"=> 1, "lock bts"=> 1, "movups"=> 1, "repne movsd"=> 1, "repne movsb"=> 1, "repne stosd"=> 1, "repne stosb"=> 1, "les"=> 1, "sldt"=> 1, "fimul"=> 1, "fiadd"=> 1, "fbstp"=> 1, "rep movsw"=> 1}
            }
            64 => {
                maplit::hashmap! {"num_functions"=> 106192, "mov"=> 86807, "ret"=> 81053, "sub"=> 74410, "add"=> 74329, "call"=> 70083, "jmp"=> 66833, "cmp"=> 55737, "xor"=> 53815, "lea"=> 53661, "je"=> 51419, "test"=> 50093, "jne"=> 49506, "push"=> 45546, "pop"=> 44960, "inc"=> 25204, "movzx"=> 23127, "movsxd"=> 22975, "or"=> 18761, "and"=> 18466, "dec"=> 17530, "nop"=> 17467, "jle"=> 15478, "jl"=> 12598, "jge"=> 11000, "jg"=> 8178, "shl"=> 7005, "jae"=> 6419, "imul"=> 6393, "jb"=> 6359, "not"=> 6213, "sar"=> 5901, "shr"=> 5792, "ja"=> 5711, "js"=> 5236, "repne scasb"=> 5180, "movsx"=> 4911, "cmove"=> 4713, "cmovne"=> 4609, "cdqe"=> 4576, "jns"=> 4120, "jbe"=> 3947, "neg"=> 3609, "sete"=> 3540, "cdq"=> 3396, "setne"=> 3283, "sbb"=> 2567, "int3"=> 2242, "cmovl"=> 1938, "cmovg"=> 1827, "movabs"=> 1307, "bt"=> 1186, "bts"=> 1087, "idiv"=> 1078, "cmovs"=> 908, "movsd"=> 860, "div"=> 854, "movaps"=> 839, "btr"=> 746, "rep movsb"=> 663, "repe cmpsb"=> 629, "cmova"=> 546, "cmovb"=> 432, "movups"=> 415, "setg"=> 362, "movd"=> 362, "setl"=> 341, "movdqa"=> 338, "lock dec"=> 336, "cmovle"=> 324, "setge"=> 319, "cvtdq2pd"=> 318, "xorpd"=> 290, "movapd"=> 281, "rep stosd"=> 279, "mulsd"=> 269, "rol"=> 256, "mul"=> 236, "cmovge"=> 231, "seta"=> 229, "addsd"=> 214, "lock inc"=> 196, "comisd"=> 194, "ror"=> 189, "subsd"=> 189, "setb"=> 185, "movdqu"=> 152, "setns"=> 137, "xchg"=> 128, "divsd"=> 124, "cmovae"=> 123, "movq"=> 119, "pxor"=> 115, "cvttsd2si"=> 114, "adc"=> 110, "rep stosb"=> 103, "setle"=> 85, "cqo"=> 84, "ucomisd"=> 83, "movnti"=> 82, "lock or"=> 82, "setbe"=> 79, "cvtsi2sd"=> 75, "jp"=> 69, "cmovbe"=> 60, "lock xadd"=> 60, "cmovns"=> 58, "movss"=> 54, "repne scasd"=> 51, "setae"=> 50, "paddd"=> 48, "cmovo"=> 46, "lock add"=> 44, "cwde"=> 44, "prefetchnta"=> 41, "bswap"=> 39, "sets"=> 39, "psrldq"=> 36, "andpd"=> 33, "pand"=> 32, "psubd"=> 32, "lock cmpxchg"=> 30, "btc"=> 29, "xorps"=> 28, "psrlq"=> 24, "psubq"=> 24, "por"=> 24, "int"=> 21, "sqrtsd"=> 20, "cvtps2pd"=> 20, "cpuid"=> 16, "stmxcsr"=> 16, "ldmxcsr"=> 16, "cvttpd2dq"=> 16, "cvtpd2dq"=> 16, "orpd"=> 16, "pshufd"=> 16, "cvtsd2ss"=> 12, "pslld"=> 12, "unpcklps"=> 9, "rep movsd"=> 9, "fld"=> 8, "fxam"=> 8, "wait"=> 8, "fnstsw"=> 8, "fnclex"=> 8, "fprem"=> 8, "fstp"=> 8, "movlpd"=> 8, "cvtsd2si"=> 8, "psrld"=> 8, "pmulld"=> 8, "jnp"=> 6, "rep movsq"=> 6, "punpckldq"=> 4, "rep stosq"=> 4, "repe cmpsd"=> 3, "comiss"=> 3, "lock bts"=> 2}
            }
            _ => return Err(Error::LogicError(file!(), line!())),
        };
        self.bitness = bitness;
        let num_documents = counts
            .remove("num_functions")
            .ok_or(Error::LogicError(file!(), line!()))?;
        for (term, term_count) in counts {
            self.idf.insert(
                term,
                self.calculate_idf(num_documents, if term_count > 0 { term_count } else { 1 })?,
            );
        }
        Ok(())
    }

    pub fn get_tfidf_from_blocks(
        &self,
        blocks: &HashMap<u64, Vec<(u64, String, String, Option<String>)>>,
    ) -> Result<f32> {
        let mut term_counts = HashMap::new();
        for block in blocks.values() {
            for ins in block {
                match term_counts.get_mut(&ins.2) {
                    Some(s) => *s += 1,
                    None => {
                        term_counts.insert(ins.2.clone(), 1);
                    }
                }
            }
        }
        self.tfidf(&term_counts)
    }

    pub fn tfidf(&self, term_counts: &HashMap<String, u32>) -> Result<f32> {
        let mut score = 0.0;
        let mut sum_term_counts = 0;
        let mut max_count = 0;
        for t in term_counts.values() {
            sum_term_counts += t;
            if max_count < *t {
                max_count = *t;
            }
        }
        for (term, term_count) in term_counts {
            score += self.calculate_tf(sum_term_counts, *term_count, max_count)?
                * self.get_frequency(term)?;
        }
        Ok(score)
    }

    fn calculate_tf(&self, _num_terms: u32, term_count: u32, _max_term_count: u32) -> Result<f32> {
        // raw count
        Ok(term_count as f32)
        // term frequency
        // return term_count / num_terms if num_terms else 0
        // double normal 0.5
        // return 0.5 + 0.5 * (term_count / max_term_count) if max_term_count else 0.5
        // log normal
        // return math.log(1 + term_count)
        // binary
        // return 1 if term_count else 0
    }

    pub fn get_frequency(&self, term: &str) -> Result<f32> {
        // if we don't have that word in our collection, use the least
        // observed frequency
        if self.idf.contains_key(term) {
            Ok(self.idf[term])
        } else {
            let mut max_idf = 0.0;
            for idf in self.idf.values() {
                if max_idf < *idf {
                    max_idf = *idf;
                }
            }
            Ok(max_idf)
        }
    }

    fn calculate_idf(&self, num_documents: u32, value_count: u32) -> Result<f32> {
        //idf probabilistic
        Ok((1.0 * (num_documents as f32 - value_count as f32) / value_count as f32).ln())
        //smooth
        //return math.log(num_documents / (1 + value_count)) + 1
        //idf
        //return math.log(num_documents / (value_count))
    }
}
