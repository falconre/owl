//! Owl is a Rust library for finding
//! [ROP](https://en.wikipedia.org/wiki/Return-oriented_programming) gadgets in
//! binary code.
//!
//! ```
//! use owl::error::*;
//! use owl::GadgetFinder;
//! use owl::X86;
//!
//! # fn example() -> Result<()> {
//! let buf = &[0x8b, 0x45, 0x3c, 0xc9, 0xc3];
//! for gadget in X86::new().find(0, buf, 16)? {
//!     println!("{:?}", gadget);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! For a more complete example, complete with ELF parsing curteousy of
//! [goblin](https://crates.io/crates/goblin), see `owl-bin` in `src/main.rs`.

#[macro_use] extern crate error_chain;
extern crate falcon_capstone;
extern crate rayon;

mod gadget;
mod mips;
mod util;
mod x86;

pub use gadget::Gadget;
pub use mips::{Mips, Mipsel};
pub use x86::{Amd64, X86};

use std::collections::HashSet;

pub mod error {
    error_chain! {
        types {
            Error, ErrorKind, ResultExt, Result;
        }

        foreign_links {
            Capstone(::falcon_capstone::capstone::CsErr);
        }
    }
}


use error::*;


/// Objects which implement GadgetFinder can find ROP gadgets.
pub trait GadgetFinder {
    fn find(&self, address: u64, bytes: &[u8], depth: usize) -> Result<Vec<Gadget>>;
}


/// Given a `Vec` of `Gadget`, deduplicates gadgets by bytes, so that there is
/// only one instance of each unique gadget.
pub fn dedup(mut gadgets: Vec<Gadget>) -> Vec<Gadget> {
    let mut set = HashSet::new();

    let mut i = 0;
    while i < gadgets.len() {
        if set.contains(gadgets[i].bytes()) {
            gadgets.remove(i);
        }
        else {
            set.insert(gadgets[i].bytes().to_owned());
            i += 1;
        }
    }

    gadgets
}