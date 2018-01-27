/// A ROP gadget
#[derive(Clone, Debug)]
pub struct Gadget {
    bytes: Vec<u8>,
    instructions: Vec<String>,
    length: usize,
    offset: usize,
}


impl Gadget {
    /// Create a new ROP gadget. This is the result of `GadgetFinder::find`.
    ///
    /// * `offset` - Offset into buffer which was searched for gadgets where
    ///              this gadget was found.
    /// * `length` - The length of this gadget in bytes.
    /// * `instructions` - The human-readable text representation of the
    ///                    instructions in this ROP gadget.
    /// * `bytes` - The bytes of the instructions in this gadget.
    pub fn new(
        offset: usize,
        length: usize,
        instructions: Vec<String>,
        bytes: Vec<u8>
    ) -> Gadget {

        Gadget {
            bytes: bytes,
            instructions: instructions,
            length: length,
            offset: offset,
        }
    }

    /// Get the bytes for this gadget.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the human-readable strings of the instructions for this gadget.
    pub fn instructions(&self) -> &[String] {
        &self.instructions
    }

    /// Get the length of this gadget in bytes.
    pub fn length(&self) -> usize {
        self.length
    }

    /// Get the offset into the searched buffer where this gadget was found.
    pub fn offset(&self) -> usize {
        self.offset
    }
}