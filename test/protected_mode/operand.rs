use yaxpeax_x86::protected_mode::{InstDecoder, Operand, RegSpec};
use yaxpeax_x86::MemoryAccessSize;

#[test]
fn register_widths() {
    assert_eq!(Operand::Register { reg: RegSpec::esp() }.width(), Some(4));
    assert_eq!(Operand::Register { reg: RegSpec::sp() }.width(), Some(2));
    assert_eq!(Operand::Register { reg: RegSpec::cl() }.width(), Some(1));
    assert_eq!(Operand::Register { reg: RegSpec::ch() }.width(), Some(1));
    assert_eq!(Operand::Register { reg: RegSpec::gs() }.width(), Some(2));
}

#[test]
fn memory_widths() {
    // the register operand directly doesn't report a size - it comes from the `Instruction` for
    // which this is an operand.
    assert_eq!(Operand::MemDeref { base: RegSpec::esp() }.width(), None);

    fn mem_size_of(data: &[u8]) -> MemoryAccessSize {
        let decoder = InstDecoder::default();
        decoder.decode_slice(data).unwrap().mem_size().unwrap()
    }

    // and checking the memory size direcly reports correct names
    assert_eq!(mem_size_of(&[0x32, 0x00]).size_name(), "byte");
    assert_eq!(mem_size_of(&[0x66, 0x33, 0x00]).size_name(), "word");
    assert_eq!(mem_size_of(&[0x33, 0x00]).size_name(), "dword");
}

#[test]
fn test_implied_memory_width() {
    fn mem_size_of(data: &[u8]) -> Option<u8> {
        let decoder = InstDecoder::default();
        decoder.decode_slice(data).unwrap().mem_size().unwrap().bytes_size()
    }

    // test push, pop, call, and ret
    assert_eq!(mem_size_of(&[0xc3]), Some(4));
    assert_eq!(mem_size_of(&[0xe8, 0x11, 0x22, 0x33, 0x44]), Some(4));
    assert_eq!(mem_size_of(&[0x50]), Some(4));
    assert_eq!(mem_size_of(&[0x58]), Some(4));
    assert_eq!(mem_size_of(&[0x66, 0x50]), Some(4));
    assert_eq!(mem_size_of(&[0x66, 0x58]), Some(4));
    assert_eq!(mem_size_of(&[0xff, 0xf0]), Some(4));
    assert_eq!(mem_size_of(&[0x66, 0xff, 0xf0]), Some(2));
    // unlike 64-bit mode, operand-size prefixed call and jump do have a different size: they read
    // two bytes.
    assert_eq!(mem_size_of(&[0x66, 0xff, 0x10]), Some(2));
    assert_eq!(mem_size_of(&[0x66, 0xff, 0x20]), Some(2));
    // pushf
    assert_eq!(mem_size_of(&[0x9c]), Some(4));
    // popf
    assert_eq!(mem_size_of(&[0x9d]), Some(4));
    // leave
    assert_eq!(mem_size_of(&[0xc9]), Some(4));
    // xlat
    assert_eq!(mem_size_of(&[0xd7]), Some(1));
    // push fs
    assert_eq!(mem_size_of(&[0x0f, 0xa0]), Some(4));
    // pop fs
    assert_eq!(mem_size_of(&[0x0f, 0xa1]), Some(4));
    // push gs
    assert_eq!(mem_size_of(&[0x0f, 0xa8]), Some(4));
    // pop gs
    assert_eq!(mem_size_of(&[0x0f, 0xa9]), Some(4));
}
