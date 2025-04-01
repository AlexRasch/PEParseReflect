#[repr(C)]
pub struct UNICODE_STRING {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}


/* --- Helpers ---*/
pub fn from_wide(slice: &[u16]) -> String {
    String::from_utf16(slice).unwrap_or_default()
}