/* --- Helpers ---*/
pub fn from_wide(slice: &[u16]) -> String {
    String::from_utf16(slice).unwrap_or_default()
}