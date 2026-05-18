#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate yaxpeax_x86;

fuzz_target!(|data: &[u8]| {
    if data.len() > 15 {
        return;
    }
    let x86_64_decoder = yaxpeax_x86::long_mode::InstDecoder::default();
    let x86_32_decoder = yaxpeax_x86::protected_mode::InstDecoder::default();
    let x86_16_decoder = yaxpeax_x86::real_mode::InstDecoder::default();

    if let Ok(inst_64b) = x86_64_decoder.decode_slice(data) {
        /*
        eprint!("x86_64: ");
        for b in data {
            eprint!("{:02x}", b);
        }
        eprintln!(": {}", inst_64b);
        */
        let behavior_64b = inst_64b.behavior();
        let _ = behavior_64b.privilege_level();
        let _ = behavior_64b.exceptions();
//        let _ = behavior_64b.implicit_oplist();
        for i in 0..5 {
            let _ = behavior_64b.operand_access(i);
        }

        let mut opcount_64b = 0;
        use yaxpeax_x86::long_mode::{Opcode as b64Opcode, Operand as b64Operand};

        if let Ok(ops) = behavior_64b.all_operands() {
            // eprintln!("checking instr {}", inst_64b);
            for (op, acc) in ops.iter() {
                match op {
                    b64Operand::ImmediateI8 { .. } |
                    b64Operand::ImmediateU8 { .. } |
                    b64Operand::ImmediateI16 { .. } |
                    b64Operand::ImmediateU16 { .. } |
                    b64Operand::ImmediateI32 { .. } |
                    b64Operand::ImmediateU32 { .. } |
                    b64Operand::ImmediateI64 { .. } => {
                        // immediates are not reported as "accessed" below, as they are not really
                        // architectural state to be "accessed".. so skip them here to make the
                        // counters line up.
                        continue;
                    },
                    _ => {}
                }
//                eprintln!("saw {:?}, {:?}", op, acc);
                let mut accs;
                if inst_64b.opcode() == b64Opcode::LEA && op.is_memory() {
                    // the access-visiting interface below does not report a memory access for lea
                    // because lea does not access memory. skip it to make the counters line up.
                    continue;
                }
                match op {
                    b64Operand::AbsoluteU32 { .. } |
                    b64Operand::AbsoluteU64 { .. } |
                    b64Operand::Register { .. } |
                    b64Operand::MemDeref { .. } |
                    b64Operand::Disp { .. } |
                    b64Operand::MemIndexScale { .. } |
                    b64Operand::MemIndexScaleDisp { .. } |
                    b64Operand::MemBaseIndexScale { .. } |
                    b64Operand::MemBaseIndexScaleDisp { .. } => {
                        accs = 1;
                    }
                    b64Operand::RegisterMaskMerge { mask, .. } |
                    b64Operand::RegisterMaskMergeSae { mask, .. } |
                    b64Operand::RegisterMaskMergeSaeNoround { mask, .. } |
                    b64Operand::MemDerefMasked { mask, .. } |
                    b64Operand::DispMasked { mask, .. } |
                    b64Operand::MemIndexScaleMasked { mask, .. } |
                    b64Operand::MemIndexScaleDispMasked { mask, .. } |
                    b64Operand::MemBaseIndexScaleMasked { mask, .. } |
                    b64Operand::MemBaseIndexScaleDispMasked { mask, .. } => {
                        accs = 1;
                        if mask.num() != 0 {
                            // the variants producing RegisterMaskMerge* are not sufficiently
                            // careful..
                            accs += 1;
                        }
                    }
                    _ => {
                        // immediates don't produce a register/memory read/write
                        accs = 0;
                    }
                }
                // read-write accesses are reported as two accesses in the visitor interface below.
                // count such cases twice here to make the counters line up.
                if acc.is_read() {
                    opcount_64b += accs;
                }
                if acc.is_write() {
                    opcount_64b += accs;
                }
            }
        }

        struct AccessCounter<'ctr> {
            counter: &'ctr mut usize,
        }

        impl<'ctr> yaxpeax_x86::long_mode::behavior::AccessVisitor for AccessCounter<'ctr> {
            fn register_read(&mut self, _reg: yaxpeax_x86::long_mode::RegSpec) {
//                eprintln!("saw read {:?}", _reg);
                *self.counter += 1;
            }
            fn register_write(&mut self, _reg: yaxpeax_x86::long_mode::RegSpec) {
//                eprintln!("saw write {:?}", _reg);
                *self.counter += 1;
            }
            fn get_register(&mut self, _reg: yaxpeax_x86::long_mode::RegSpec) -> Option<u64> { None }
            fn memory_read(&mut self, _address: Option<u64>, _size: u32) {
//                eprintln!("saw read {:?}", _size);
                *self.counter += 1;
            }
            fn memory_write(&mut self, _address: Option<u64>, _size: u32) {
//                eprintln!("saw write {:?}", _size);
                *self.counter += 1;
            }
        }

        let mut acc_seen_64b = 0;
        let mut visitor = AccessCounter {
            counter: &mut acc_seen_64b,
        };

        let visit_res = behavior_64b.visit_accesses(&mut visitor);
        if visit_res.is_ok() {
            assert_eq!(opcount_64b, acc_seen_64b);
        }
    }

    if let Ok(inst_32b) = x86_32_decoder.decode_slice(data) {
        /*
        eprint!("x86_32: ");
        for b in data {
            eprint!("{:02x}", b);
        }
        eprintln!(": {}", inst_32b);
        */
        let behavior_32b = inst_32b.behavior();
        let _ = behavior_32b.privilege_level();
        let _ = behavior_32b.exceptions();
//        let _ = behavior_32b.implicit_oplist();
        for i in 0..5 {
            let _ = behavior_32b.operand_access(i);
        }

        let mut opcount_32b = 0;
        use yaxpeax_x86::protected_mode::{Opcode as b32Opcode, Operand as b32Operand};

        if let Ok(ops) = behavior_32b.all_operands() {
            // eprintln!("checking instr {}", inst_32b);
            for (op, acc) in ops.iter() {
                match op {
                    b32Operand::ImmediateI8 { .. } |
                    b32Operand::ImmediateU8 { .. } |
                    b32Operand::ImmediateI16 { .. } |
                    b32Operand::ImmediateU16 { .. } |
                    b32Operand::ImmediateI32 { .. } |
                    b32Operand::ImmediateU32 { .. } => {
                        // immediates are not reported as "accessed" below, as they are not really
                        // architectural state to be "accessed".. so skip them here to make the
                        // counters line up.
                        continue;
                    },
                    _ => {}
                }
//                eprintln!("saw {:?}, {:?}", op, acc);
                let mut accs;
                if inst_32b.opcode() == b32Opcode::LEA && op.is_memory() {
                    // the access-visiting interface below does not report a memory access for lea
                    // because lea does not access memory. skip it to make the counters line up.
                    continue;
                }
                match op {
                    b32Operand::AbsoluteU16 { .. } |
                    b32Operand::AbsoluteU32 { .. } |
                    b32Operand::Register { .. } |
                    b32Operand::MemDeref { .. } |
                    b32Operand::Disp { .. } |
                    b32Operand::MemIndexScale { .. } |
                    b32Operand::MemIndexScaleDisp { .. } |
                    b32Operand::MemBaseIndexScale { .. } |
                    b32Operand::MemBaseIndexScaleDisp { .. } => {
                        accs = 1;
                    }
                    b32Operand::RegisterMaskMerge { mask, .. } |
                    b32Operand::RegisterMaskMergeSae { mask, .. } |
                    b32Operand::RegisterMaskMergeSaeNoround { mask, .. } |
                    b32Operand::MemDerefMasked { mask, .. } |
                    b32Operand::DispMasked { mask, .. } |
                    b32Operand::MemIndexScaleMasked { mask, .. } |
                    b32Operand::MemIndexScaleDispMasked { mask, .. } |
                    b32Operand::MemBaseIndexScaleMasked { mask, .. } |
                    b32Operand::MemBaseIndexScaleDispMasked { mask, .. } => {
                        accs = 1;
                        if mask.num() != 0 {
                            // the variants producing RegisterMaskMerge* are not sufficiently
                            // careful..
                            accs += 1;
                        }
                    }
                    _ => {
                        // immediates don't produce a register/memory read/write
                        accs = 0;
                    }
                }
                // read-write accesses are reported as two accesses in the visitor interface below.
                // count such cases twice here to make the counters line up.
                if acc.is_read() {
                    opcount_32b += accs;
                }
                if acc.is_write() {
                    opcount_32b += accs;
                }
            }
        }

        struct AccessCounter<'ctr> {
            counter: &'ctr mut usize,
        }

        impl<'ctr> yaxpeax_x86::protected_mode::behavior::AccessVisitor for AccessCounter<'ctr> {
            fn register_read(&mut self, _reg: yaxpeax_x86::protected_mode::RegSpec) {
//                eprintln!("saw read {:?}", _reg);
                *self.counter += 1;
            }
            fn register_write(&mut self, _reg: yaxpeax_x86::protected_mode::RegSpec) {
//                eprintln!("saw write {:?}", _reg);
                *self.counter += 1;
            }
            fn get_register(&mut self, _reg: yaxpeax_x86::protected_mode::RegSpec) -> Option<u32> { None }
            fn memory_read(&mut self, _address: Option<u32>, _size: u32) {
//                eprintln!("saw read {:?}", _size);
                *self.counter += 1;
            }
            fn memory_write(&mut self, _address: Option<u32>, _size: u32) {
//                eprintln!("saw write {:?}", _size);
                *self.counter += 1;
            }
        }

        let mut acc_seen_32b = 0;
        let mut visitor = AccessCounter {
            counter: &mut acc_seen_32b,
        };

        let visit_res = behavior_32b.visit_accesses(&mut visitor);
        if visit_res.is_ok() {
            assert_eq!(opcount_32b, acc_seen_32b);
        }
    }

    if let Ok(inst_16b) = x86_16_decoder.decode_slice(data) {
        /*
        eprint!("x86_16: ");
        for b in data {
            eprint!("{:02x}", b);
        }
        eprintln!(": {}", inst_16b);
        */
        let behavior_16b = inst_16b.behavior();
        let _ = behavior_16b.privilege_level();
        let _ = behavior_16b.exceptions();
//        let _ = behavior_16b.implicit_oplist();
        for i in 0..5 {
            let _ = behavior_16b.operand_access(i);
        }

        let mut opcount_16b = 0;
        use yaxpeax_x86::real_mode::{Opcode as b16Opcode, Operand as b16Operand};

        if let Ok(ops) = behavior_16b.all_operands() {
            // eprintln!("checking instr {}", inst_16b);
            for (op, acc) in ops.iter() {
                match op {
                    b16Operand::ImmediateI8 { .. } |
                    b16Operand::ImmediateU8 { .. } |
                    b16Operand::ImmediateI16 { .. } |
                    b16Operand::ImmediateU16 { .. } |
                    b16Operand::ImmediateI32 { .. } |
                    b16Operand::ImmediateU32 { .. } => {
                        // immediates are not reported as "accessed" below, as they are not really
                        // architectural state to be "accessed".. so skip them here to make the
                        // counters line up.
                        continue;
                    },
                    _ => {}
                }
//                eprintln!("saw {:?}, {:?}", op, acc);
                let mut accs;
                if inst_16b.opcode() == b16Opcode::LEA && op.is_memory() {
                    // the access-visiting interface below does not report a memory access for lea
                    // because lea does not access memory. skip it to make the counters line up.
                    continue;
                }
                match op {
                    b16Operand::AbsoluteU16 { .. } |
                    b16Operand::AbsoluteU32 { .. } |
                    b16Operand::Register { .. } |
                    b16Operand::MemDeref { .. } |
                    b16Operand::MemDisp { .. } |
                    b16Operand::MemIndexScale { .. } |
                    b16Operand::MemIndexScaleDisp { .. } |
                    b16Operand::MemBaseIndexScale { .. } |
                    b16Operand::MemBaseIndexScaleDisp { .. } => {
                        accs = 1;
                    }
                    b16Operand::RegisterMaskMerge { mask, .. } |
                    b16Operand::RegisterMaskMergeSae { mask, .. } |
                    b16Operand::RegisterMaskMergeSaeNoround { mask, .. } |
                    b16Operand::MemDerefMasked { mask, .. } |
                    b16Operand::MemDispMasked { mask, .. } |
                    b16Operand::MemIndexScaleMasked { mask, .. } |
                    b16Operand::MemIndexScaleDispMasked { mask, .. } |
                    b16Operand::MemBaseIndexScaleMasked { mask, .. } |
                    b16Operand::MemBaseIndexScaleDispMasked { mask, .. } => {
                        accs = 1;
                        if mask.num() != 0 {
                            // the variants producing RegisterMaskMerge* are not sufficiently
                            // careful..
                            accs += 1;
                        }
                    }
                    _ => {
                        // immediates don't produce a register/memory read/write
                        accs = 0;
                    }
                }
                // read-write accesses are reported as two accesses in the visitor interface below.
                // count such cases twice here to make the counters line up.
                if acc.is_read() {
                    opcount_16b += accs;
                }
                if acc.is_write() {
                    opcount_16b += accs;
                }
            }
        }

        struct AccessCounter<'ctr> {
            counter: &'ctr mut usize,
        }

        impl<'ctr> yaxpeax_x86::real_mode::behavior::AccessVisitor for AccessCounter<'ctr> {
            fn register_read(&mut self, _reg: yaxpeax_x86::real_mode::RegSpec) {
//                eprintln!("saw read {:?}", _reg);
                *self.counter += 1;
            }
            fn register_write(&mut self, _reg: yaxpeax_x86::real_mode::RegSpec) {
//                eprintln!("saw write {:?}", _reg);
                *self.counter += 1;
            }
            fn get_register(&mut self, _reg: yaxpeax_x86::real_mode::RegSpec) -> Option<u16> { None }
            fn memory_read(&mut self, _address: Option<u16>, _size: u32) {
//                eprintln!("saw read {:?}", _size);
                *self.counter += 1;
            }
            fn memory_write(&mut self, _address: Option<u16>, _size: u32) {
//                eprintln!("saw write {:?}", _size);
                *self.counter += 1;
            }
        }

        let mut acc_seen_16b = 0;
        let mut visitor = AccessCounter {
            counter: &mut acc_seen_16b,
        };

        let visit_res = behavior_16b.visit_accesses(&mut visitor);
        if visit_res.is_ok() {
            assert_eq!(opcount_16b, acc_seen_16b);
        }
    }
});
