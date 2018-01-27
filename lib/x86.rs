use error::*;
use falcon_capstone::capstone;
use gadget::*;
use util::find;


/// A ROP-gadget finder for the x86 (32-bit) architecture.
#[derive(Clone, Debug)]
pub struct X86 {}


impl X86 {
    /// Create a new x86 ROP-Gadget finder.
    pub fn new() -> X86 {
        X86 {}
    }

    /// Find ROP-Gadgets in x86 code.
    pub fn find(&self, address: u64, bytes: &[u8], depth: usize) -> Result<Vec<Gadget>> {
        find(address,
             bytes,
             depth,
             1,
             capstone::cs_arch::CS_ARCH_X86,
             capstone::CS_MODE_32,
             RET_INSTRUCTIONS,
             VALID_INSTRUCTIONS)
    }
}


impl ::GadgetFinder for X86 {
    fn find(&self, address: u64, bytes: &[u8], depth: usize) -> Result<Vec<Gadget>> {
        self.find(address, bytes, depth)
    }
}


static VALID_INSTRUCTIONS: &[capstone::InstrIdArch] = &[
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_ADC),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_ADD),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_AND),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_BSF),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_BSR),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_BSWAP),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_BT),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_BTC),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_BTR),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_BTS),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_CBW),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_CDQ),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_CLC),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_CLD),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_CLI),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_CMC),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_CMOVA),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_CMOVAE),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_CMOVB),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_CMOVBE),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_CMOVE),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_CMOVG),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_CMOVGE),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_CMOVL),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_CMOVLE),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_CMOVNE),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_CMOVNO),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_CMOVNP),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_CMOVNS),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_CMOVO),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_CMOVP),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_CMOVS),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_CMP),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_CMPSB),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_CMPXCHG),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_CWD),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_CWDE),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_DEC),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_DIV),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_IDIV),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_IMUL),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_INC),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_LEA),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_LEAVE),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_LODSB),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_LOOP),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_LOOPE),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_LOOPNE),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_MOV),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_MOVSB),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_MOVSW),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_MOVSD),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_MOVSX),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_MOVZX),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_MUL),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_NEG),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_NOP),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_NOT),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_OR),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_POP),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_PUSH),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_ROL),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_ROR),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_SAR),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_SBB),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_SETAE),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_SETA),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_SETBE),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_SETB),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_SETE),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_SETGE),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_SETG),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_SETLE),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_SETL),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_SETNE),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_SETNO),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_SETNP),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_SETNS),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_SETO),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_SETP),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_SETS),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_SHL),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_SHR),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_SHLD),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_SHRD),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_STC),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_STD),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_STI),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_STOSB),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_STOSW),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_STOSD),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_SUB),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_TEST),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_XADD),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_XCHG),
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_XOR)
];


static RET_INSTRUCTIONS: &[capstone::InstrIdArch] = &[
    capstone::InstrIdArch::X86(capstone::x86_insn::X86_INS_RET)
];