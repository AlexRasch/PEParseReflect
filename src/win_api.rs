#[link(name = "kernel32")]
#[allow(non_snake_case)]
unsafe extern "system" {
    pub fn lstrcmpiW(lpString1: *const u16, lpString2: *const u16) -> i32;
}
