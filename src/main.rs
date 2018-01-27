extern crate clap;
extern crate goblin;
extern crate owl;

use clap::{Arg, App};
use owl::*;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;


fn do_elf(file: &[u8], elf: &goblin::elf::Elf) {
    let mut gadgets = BTreeMap::new();

    let gadget_finder: Box<GadgetFinder> = match elf.header.e_machine {
        goblin::elf::header::EM_386 => Box::new(X86::new()),
        goblin::elf::header::EM_MIPS => Box::new(Mips::new()),
        _ => panic!("Unsupported architecture")
    };

    for program_header in &elf.program_headers {
        if program_header.p_flags & goblin::elf::program_header::PF_X == 0 {
            continue;
        }

        let vaddr = program_header.p_vaddr;
        let offset = program_header.p_offset as usize;
        let length = program_header.p_filesz as usize;
        println!("{},{}", offset, length);
        gadgets.insert(
            vaddr,
            gadget_finder.find(
                vaddr,
                file.get(offset..(offset + length)).expect("Failed to load from file"),
                16).unwrap()
        );
    }

    for (address, gadgets) in gadgets {
        for gadget in gadgets {
            println!("{:0x}", address + gadget.offset() as u64);
            for instruction in gadget.instructions() {
                println!("  {}", instruction);
            }
        }
    }
}


fn main () {
    let matches = App::new("owl")
        .version("0.0.1")
        .author("Alex Eubanks <alex.eubanks@forallsecure.com")
        .about("ROP Gadget Finder")
        .arg(Arg::with_name("program")
            .required(true)
            .index(1))
        .get_matches();

    let filename = matches.value_of("program").unwrap();
    let path = Path::new(&filename);
    let mut fd = File::open(path).unwrap();

    let mut data = Vec::new();
    fd.read_to_end(&mut data).unwrap();
    match goblin::Object::parse(&data).unwrap() {
        goblin::Object::Elf(elf) => {
            do_elf(&data, &elf);
        },
        _ => println!("Unsupported file format")
    }
}