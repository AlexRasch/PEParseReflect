/* --- PE Helpers ---*/
use crate::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS};

/// Resolves the address of a function by searching the export section of a PE module.
///
/// This function locates the export directory in the PE file, iterates through the exported
/// function names, and compares each with the provided `func_name`. If a match is found,
/// it returns the address of the corresponding function. If the function is not found,
/// it returns `None`.
///
/// # Arguments
/// - `module_base`: A pointer to the base address of the loaded module.
/// - `func_name`: The name of the function to resolve in the export table.
///
/// # Returns
/// - `Some(*mut u8)`: The address of the resolved function, if found.
/// - `None`: If the function could not be found in the export table.
pub unsafe fn resolve_function(module_base: *mut u8, func_name: &str) -> Option<*mut u8> {
    unsafe {

        if !validate_pe(module_base){
            return None;
        }

        let dos_header = module_base as *const IMAGE_DOS_HEADER;
        let nt_headers_addr = (module_base as usize).wrapping_add((*dos_header).e_lfanew as usize);
        let nt_headers = nt_headers_addr as *const IMAGE_NT_HEADERS;

        let export_dir = &(*nt_headers).optional_header.data_directory[0];
        if export_dir.virtual_address == 0 || export_dir.size == 0 {
            #[cfg(debug_assertions)]
            //println!("No export directory found");
            return None;
        }

        let export_table_addr = (module_base as usize).wrapping_add(export_dir.virtual_address as usize);
        if export_table_addr % 4 != 0 {
            #[cfg(debug_assertions)]
            //println!("Misaligned export table address: {:x}", export_table_addr);
            return None;
        }
        let export_table = export_table_addr as *const IMAGE_EXPORT_DIRECTORY;

        let number_of_names = (*export_table).number_of_names;
        if number_of_names == 0 {
            #[cfg(debug_assertions)]
            //println!("No exported names");
            return None;
        }

        let name_ptrs = (module_base as usize + (*export_table).address_of_names as usize) as *const u32;
        let ordinals = (module_base as usize + (*export_table).address_of_name_ordinals as usize) as *const u16;
        let functions = (module_base as usize + (*export_table).address_of_functions as usize) as *const u32;

        for i in 0..(*export_table).number_of_names {
            let name_rva = *name_ptrs.add(i as usize);
            let name_addr = (module_base as usize + name_rva as usize) as *const i8;
            let name_str = core::ffi::CStr::from_ptr(name_addr).to_str().unwrap_or("");

            if name_str == func_name {
                let ordinal = *ordinals.add(i as usize) as usize;
                let func_rva = *functions.add(ordinal);
                let func_addr = (module_base as usize + func_rva as usize) as *mut u8;
                return Some(func_addr);
            }
        }
    }
    //println!("{} not found", func_name);
    None
}

/// Validates if the given module base points to a well-formed 64-bit PE (Portable Executable) file.
///
/// This function performs the following checks:
/// 1. Validates that the DOS header contains the "MZ" signature.
/// 2. Ensures that the e_lfanew field is correctly set and aligned.
/// 3. Validates the NT headers and checks for the "PE" signature.
/// 4. Confirms that the file is a 64-bit PE (PE32+).
///
/// # Arguments
/// * `module_base` - A pointer to the base address of the module to validate.
///
/// # Returns
/// * `true` if the module is a valid 64-bit PE file, otherwise `false`.
pub unsafe fn validate_pe(module_base: *mut u8) -> bool {
    unsafe {
        let dos_header = module_base as *const IMAGE_DOS_HEADER;
        if !validate_dos_header(dos_header) {
            return false;
        }

        let e_lfanew = (*dos_header).e_lfanew;
        if !validate_e_lfanew(e_lfanew) {
            return false;
        }

        let nt_headers_addr = (module_base as usize).wrapping_add(e_lfanew as usize);
        let nt_headers = nt_headers_addr as *const IMAGE_NT_HEADERS;

        if !validate_pe_signature(nt_headers) {
            return false;
        }

        if !validate_pe64(nt_headers) {
            return false;
        }

        true
    }
}

/// Validates the DOS header by checking for the "MZ" signature (0x5A4D) at the beginning of a valid PE file.
///
/// ## Parameters
/// - `dos_header`: A pointer to the `IMAGE_DOS_HEADER` structure to validate.
///
/// ## Returns
/// Returns `true` if the DOS header is valid (contains "MZ" signature), otherwise `false`.
pub unsafe fn validate_dos_header(dos_header: *const IMAGE_DOS_HEADER) -> bool {
    if dos_header.is_null() {
        #[cfg(debug_assertions)]
        //println!("Null DOS header pointer");
        return false;
    }

    let magic = unsafe { (*dos_header).e_magic };
    if magic == 0x5A4D {
        return true;
    }

    //#[cfg(debug_assertions)]
    //println!("Invalid DOS magic");

    return false
}

/// Validates the e_lfanew field, ensuring it is within a reasonable range and properly aligned for NT headers.
///
/// ## Parameters
/// - `e_lfanew`: The offset (in bytes) from the beginning of the file to the start of the NT headers.
///
/// ## Returns
/// Returns `true` if the e_lfanew is valid and properly aligned, otherwise `false`.
pub unsafe fn validate_e_lfanew(e_lfanew: i32) -> bool {
    // Se till att e_lfanew är positiv och inom rimligt intervall
    if e_lfanew < 0x40 || e_lfanew > 0x1000 {
        //#[cfg(debug_assertions)]
        //println!("Invalid e_lfanew: {}", e_lfanew);
        return false;
    }
    // Kontrollera 4-byte alignment
    if e_lfanew % 4 != 0 {
        //#[cfg(debug_assertions)]
        //println!("Misaligned e_lfanew: {}", e_lfanew);
        return false;
    }
    return true;
}

/// Validates the PE signature by checking for "PE" (0x4550) to confirm the correct position in the file.
///
/// ## Parameters
/// - `nt_headers`: A pointer to the `IMAGE_NT_HEADERS` structure to validate.
///
/// ## Returns
/// Returns `true` if the PE signature is valid, otherwise `false`.
pub unsafe fn validate_pe_signature(nt_headers: *const IMAGE_NT_HEADERS) -> bool {
    if nt_headers.is_null() {
        #[cfg(debug_assertions)]
        //println!("Null NT headers");
        return false;
    }
    unsafe {
        if (*nt_headers).signature != 0x4550 {
            #[cfg(debug_assertions)]
            //println!("Invalid PE signature");
            return false;
        }
    }
    true
}

/// Checks if the PE file is 64-bit (PE32+ format) by validating optional_header.magic.
///
/// ## Parameters
/// - `nt_headers`: A pointer to the `IMAGE_NT_HEADERS` structure to validate.
///
/// ## Returns
/// - `true` if the PE file is 64-bit (PE32+).
/// - `false` if the pointer is null or the magic value is incorrect.
pub unsafe fn validate_pe64(nt_headers : *const IMAGE_NT_HEADERS) -> bool {
    if nt_headers.is_null(){
        #[cfg(debug_assertions)]
        //println!("Null NT headers");
        return false;
    }
    unsafe {
        return (*nt_headers).optional_header.magic == 0x20B;
    }
}