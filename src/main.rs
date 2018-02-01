extern crate clap;
extern crate goblin;
extern crate owl;

use clap::{Arg, App};
use owl::*;
use std::fs::File;
use std::io::Read;
use std::path::Path;


fn do_elf(file: &[u8], elf: &goblin::elf::Elf, filter: Option<&str>) {
    // Figure out which ROP-Gadget finder to use based on ELF header.
    let gadget_finder: Box<GadgetFinder> = match elf.header.e_machine {
        goblin::elf::header::EM_386 => Box::new(X86::new()),
        goblin::elf::header::EM_X86_64 => Box::new(Amd64::new()),
        goblin::elf::header::EM_MIPS => match elf.header.endianness().unwrap() {
            goblin::container::Endian::Big => Box::new(Mips::new()),
            goblin::container::Endian::Little => Box::new(Mipsel::new())
        },
        _ => panic!("Unsupported architecture")
    };


    let mut gadgets = Vec::new();

    // Walk executable program headers, and find gadgets in the executable.
    for program_header in &elf.program_headers {
        if program_header.p_flags & goblin::elf::program_header::PF_X == 0 {
            continue;
        }

        let vaddr = program_header.p_vaddr;
        let offset = program_header.p_offset as usize;
        let length = program_header.p_filesz as usize;
        
        gadgets.append(
            // get the gadget for this PHDR
            &mut gadget_finder.find(
                    vaddr,
                    file.get(offset..(offset + length)).expect("Failed to load from file"),
                    16)
                .unwrap()
                // Apply the virtual address of this PHDR to the offset of the
                // gadgets
                .into_iter()
                .map(|mut gadget| {
                    let offset = gadget.offset();
                    gadget.set_offset(vaddr + offset);
                    gadget
                })
                .collect());
    }

    // Deduplicate the gadgets
    let gadgets = dedup(gadgets);

    // Print out the gadgets
    for gadget in gadgets {
        let bytes =
            gadget.bytes()
                  .iter()
                  .map(|byte| format!("{:02x}", byte))
                  .collect::<Vec<String>>()
                  .join(" ");
        if let Some(filter) = filter {
            if !gadget.instructions()
                      .iter()
                      .fold(false, |matches, instruction| 
                        matches | instruction.contains(filter)) {
                continue;
            }
        }
        println!("{:0x}: {}", gadget.offset(), bytes);
        for instruction in gadget.instructions() {
            println!("  {}", instruction);
        }
    }
}


fn main () {
    // Use clap for command-line argument parsing.
    let matches = App::new("owl")
        .author("Alex Eubanks <endeavor@rainbowsandpwnies.com>")
        .about("ROP Gadget Finder")
        .arg(Arg::with_name("filter")
            .short("f")
            .value_name("filter")
            .help("Filter rop gadgets by substring"))
        .arg(Arg::with_name("program")
            .required(true)
            .index(1))
        .get_matches();

    // Read in our program.
    let filename = matches.value_of("program").unwrap();
    let path = Path::new(&filename);
    let mut fd = File::open(path).unwrap();

    let mut data = Vec::new();
    fd.read_to_end(&mut data).unwrap();
    
    // Parse the file with Elf.
    match goblin::Object::parse(&data).unwrap() {
        goblin::Object::Elf(elf) => {
            do_elf(&data, &elf, matches.value_of("filter"));
        },
        _ => println!("Unsupported file format")
    }
}