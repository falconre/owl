use error::*;
use falcon_capstone::capstone;
use Gadget;
use rayon::prelude::*;


pub(crate) fn find(
    address: u64,
    bytes: &[u8],
    depth: usize,
    minimum_instruction_width: usize,
    arch: capstone::cs_arch,
    mode: capstone::cs_mode,
    ret_instructions: &[capstone::InstrIdArch],
    valid_instructions: &[capstone::InstrIdArch],
    delay_slot: usize
) -> Result<Vec<Gadget>> {

    let gadgets = (0..bytes.len() / minimum_instruction_width)
        .into_par_iter()
        .fold(|| Vec::new(), |mut gadgets, offset| {

            let offset = offset * minimum_instruction_width;

            let cs = capstone::Capstone::new(arch, mode)
                .expect("Failed to instantiate capstone");

            'depth: for _ in 0..depth {
                let top = if offset + depth > bytes.len() {
                    bytes.len()
                } else {
                    offset + depth
                };
                let disassembly_range = offset..top;
                let disassembly_bytes = bytes.get(disassembly_range).unwrap();
                let instructions = match cs.disasm(disassembly_bytes,
                                                address + offset as u64,
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
                        let bytes =
                            match disassembly_bytes.get(0..(length + delay_slot)) {
                                Some(bytes) => bytes,
                                None => { continue; }
                            };
                        gadgets.push(Gadget::new(offset as u64, instrs, bytes.to_vec()));
                        break 'depth;
                    }
                    else if !valid_instructions.contains(&instruction.id) {
                        break;
                    }
                }
            }
            gadgets
        })
        .reduce(|| Vec::new(), |mut a, mut b| {
            a.append(&mut b);
            a
        });

    Ok(gadgets)
}