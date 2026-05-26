#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate yaxpeax_x86;
extern crate yaxpeax_arch;

fuzz_target!(|data: &[u8]| {
    if data.len() > 15 {
        return;
    }

    let x86_64_decoder = yaxpeax_x86::long_mode::InstDecoder::default();
    let x86_32_decoder = yaxpeax_x86::protected_mode::InstDecoder::default();
    let x86_16_decoder = yaxpeax_x86::real_mode::InstDecoder::default();

    use yaxpeax_arch::testkit::DisplaySinkValidator;

    if let Ok(inst) = x86_64_decoder.decode_slice(data) {
        inst.display_into(&mut DisplaySinkValidator::new()).expect("instruction can be displayed");
    };

    if let Ok(inst) = x86_32_decoder.decode_slice(data) {
        inst.display_into(&mut DisplaySinkValidator::new()).expect("instruction can be displayed");
    };

    if let Ok(inst) = x86_16_decoder.decode_slice(data) {
        inst.display_into(&mut DisplaySinkValidator::new()).expect("instruction can be displayed");
    };
});
