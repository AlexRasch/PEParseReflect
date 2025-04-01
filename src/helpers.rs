#[repr(C)]
pub struct UNICODE_STRING {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}

