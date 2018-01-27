use error::*;
use falcon_capstone::capstone;
use Gadget;


pub(crate) fn find(
    address: u64,
    bytes: &[u8],
    depth: usize,
    minimum_instruction_width: usize,
    arch: capstone::cs_arch,
    mode: capstone::cs_mode,
    ret_instructions: &[capstone::InstrIdArch],
    valid_instructions: &[capstone::InstrIdArch]
) -> Result<Vec<Gadget>> {
    let mut gadgets = Vec::new();

    let cs = capstone::Capstone::new(arch, mode)?;

    let mut i = 0;
    while i < bytes.len() {
        'depth: for _ in 0..depth {
            let top = if i + depth > bytes.len() {
                bytes.len()
            } else {
                i + depth
            };
            let disassembly_range = i..top;
            let disassembly_bytes = bytes.get(disassembly_range).unwrap();
            let instructions = match cs.disasm(disassembly_bytes,
                                               address + i as u64,
                                               depth) {
                Ok(instructions) => instructions,
                Err(_) => continue
            };

            let mut instrs: Vec<String> = Vec::new();

            let mut length: usize = 0;

            for instruction in instructions.iter() {
                length += instruction.size as usize;
                instrs.push(format!("{} {}", instruction.mnemonic, instruction.op_str));

                if ret_instructions.contains(&instruction.id) {
                    let offset = i as u64;
                    let bytes =
                        disassembly_bytes.get(0..length)
                                         .ok_or("Failed to get bytes")?
                                         .to_vec();
                    gadgets.push(Gadget::new(offset, instrs, bytes));
                    break 'depth;
                }
                else if !valid_instructions.contains(&instruction.id) {
                    break;
                }
            }
        }
        i += minimum_instruction_width;
    }

    Ok(gadgets)
}