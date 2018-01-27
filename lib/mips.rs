use error::*;
use falcon_capstone::capstone;
use gadget::*;
use util::find;

/// A ROP-gadget finder for the MIPS (Big-Endian) architecture.
#[derive(Clone, Debug)]
pub struct Mips {}

/// A ROP-gadget finder for the MIPSEL (Little-Endian) architecture.
#[derive(Clone, Debug)]
pub struct Mipsel {}


impl Mips {
    /// Create a new Mips ROP-Gadget finder.
    pub fn new() -> Mips {
        Mips {}
    }

    /// Find ROP-Gadgets in MIPS code.
    pub fn find(&self, address: u64, bytes: &[u8], depth: usize) -> Result<Vec<Gadget>> {
        find(address,
             bytes,
             depth,
             4,
             capstone::cs_arch::CS_ARCH_MIPS,
             capstone::CS_MODE_32 | capstone::CS_MODE_BIG_ENDIAN,
             RET_INSTRUCTIONS,
             VALID_INSTRUCTIONS)
    }
}


impl ::GadgetFinder for Mips {
    fn find(&self, address: u64, bytes: &[u8], depth: usize) -> Result<Vec<Gadget>> {
        self.find(address, bytes, depth)
    }
}


impl Mipsel {
    /// Create a new Mipsel ROP-Gadget finder.
    pub fn new() -> Mipsel {
        Mipsel {}
    }

    /// Find ROP-Gadgets in Mipsel code.
    pub fn find(&self, address: u64, bytes: &[u8], depth: usize) -> Result<Vec<Gadget>> {
        find(address,
             bytes,
             depth,
             4,
             capstone::cs_arch::CS_ARCH_MIPS,
             capstone::CS_MODE_32 | capstone::CS_MODE_LITTLE_ENDIAN,
             RET_INSTRUCTIONS,
             VALID_INSTRUCTIONS)
    }
}


impl ::GadgetFinder for Mipsel {
    fn find(&self, address: u64, bytes: &[u8], depth: usize) -> Result<Vec<Gadget>> {
        self.find(address, bytes, depth)
    }
}


static VALID_INSTRUCTIONS: &[capstone::InstrIdArch] = &[
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_ADD),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_ADDI),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_ADDIU),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_ADDU),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_AND),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_ANDI),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_CLO),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_CLZ),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_DIV),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_DIVU),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_LB),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_LBU),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_LH),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_LHU),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_LUI),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_LW),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_MADD),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_MADDU),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_MFHI),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_MFLO),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_MOVE),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_MOVN),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_MOVZ),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_MSUB),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_MSUBU),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_MTHI),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_MTLO),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_MUL),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_MULT),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_MULTU),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_NEGU),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_NOP),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_NOR),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_OR),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_ORI),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_SB),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_SH),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_SLL),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_SLLV),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_SLT),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_SLTI),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_SLTIU),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_SLTU),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_SRA),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_SRAV),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_SRL),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_SRLV),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_SUB),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_SUBU),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_SW),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_XOR),
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_XORI),
];


static RET_INSTRUCTIONS: &[capstone::InstrIdArch] = &[
    capstone::InstrIdArch::MIPS(capstone::mips_insn::MIPS_INS_JR)
];