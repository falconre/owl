/// A ROP gadget
#[derive(Clone, Debug)]
pub struct Gadget {
    bytes: Vec<u8>,
    instructions: Vec<String>,
    offset: u64,
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
        offset: u64,
        instructions: Vec<String>,
        bytes: Vec<u8>
    ) -> Gadget {

        Gadget {
            bytes: bytes,
            instructions: instructions,
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
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Get the offset into the searched buffer where this gadget was found.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Set the bytes for this gadget.
    pub fn set_bytes(&mut self, bytes: Vec<u8>) {
        self.bytes = bytes;
    }

    /// Set the instruction strings for this gadget.
    pub fn set_instructions(&mut self, instructions: Vec<String>) {
        self.instructions = instructions;
    }

    /// Set offset for this gadget
    pub fn set_offset(&mut self, offset: u64) {
        self.offset = offset;
    }
}