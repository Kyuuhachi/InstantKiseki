#[no_mangle]
pub extern "C" fn lb_init() {
	println!("InstantKiseki: init");

	unsafe {
		const MASK: u32 = 0xC000190;
		const START: *const u8 = 0x00400000 as *const u8;
		let pos = {
			let haystack = std::slice::from_raw_parts(START, 0x00200000);
			memchr::memmem::find(haystack, &MASK.to_ne_bytes())
				.expect("Failed to find signature")
		};
		let ptr = START.byte_add(pos).byte_sub(2) as *mut [u8; 2];
		region::protect(ptr, 2, region::Protection::READ_WRITE_EXECUTE).unwrap();

		match ptr.read() {
			[0x81, 0xE6] => ptr.write([0x81, 0xCE]), // FC: and esi, MASK => or esi, MASK
			[0x81, 0xE7] => ptr.write([0x81, 0xCF]), // SC&3rd: and edi, MASK => or edi, MASK
			_ => panic!("Found signature, but wrong instruction"),
		};
	}
}
