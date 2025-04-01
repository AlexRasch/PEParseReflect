#![no_main]
//#![no_std]

use core::arch::asm;
use core::slice;
use core::ptr;


// Strukturer
#[repr(C)]
struct LIST_ENTRY {
    flink: *mut LIST_ENTRY,
    blink: *mut LIST_ENTRY,
}

#[repr(C)]
struct UNICODE_STRING {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct PEB_LDR_DATA {
    _pad: [u8; 16],
    in_memory_order_module_list: LIST_ENTRY,
}

#[repr(C)]
struct LDR_DATA_TABLE_ENTRY {
    in_load_order_links: LIST_ENTRY,
    in_memory_order_links: LIST_ENTRY,
    in_initialization_order_links: LIST_ENTRY,
    dll_base: *mut u8,
    entry_point: *mut u8,
    size_of_image: u32,
    full_dll_name: UNICODE_STRING,
    base_dll_name: UNICODE_STRING,
}

#[repr(C)]
struct TEB {
    _pad: [u8; 0x60], // Offset till PEB i TEB-strukturen
    process_environment_block: *mut PEB,
}

#[repr(C)]
struct PEB {
    _pad: [u8; 24], // Offset till LDR i PEB-strukturen
    ldr: *mut PEB_LDR_DATA,
}

unsafe fn get_teb() -> *mut TEB {
    let teb: *mut TEB;
    unsafe {
        asm!("mov {}, gs:[0x30]", out(reg) teb);
    }
    teb
}

// Hämta PEB via TEB, tack Mario
fn get_peb() -> *mut PEB {
    unsafe {
        let teb = get_teb();
        (*teb).process_environment_block
    }
}

fn get_module_bases() -> (Option<*mut u8>, Option<*mut u8>) {
    let peb = get_peb();
    let ldr = unsafe { (*peb).ldr };

    if ldr.is_null() {
        println!("LDR is null");
        return (None,None);
    }

    // Start from first post inside `in_memory_order_module_list`
    let mut entry = unsafe { (*ldr).in_memory_order_module_list.flink };
    let list_head = entry;

    let mut ntdll_base: Option<*mut u8> = None;
    let mut kernelbase_base: Option<*mut u8> = None;

    while !entry.is_null() {
        let ldr_entry = entry as *mut LDR_DATA_TABLE_ENTRY;
        let base = unsafe { (*ldr_entry).dll_base };
        let name_ref = unsafe { &(*ldr_entry).base_dll_name };

        if !name_ref.buffer.is_null() {
            // Konvertera UNICODE_STRING till en Rust-sträng
            let name_slice = unsafe {
                core::slice::from_raw_parts(name_ref.buffer, (name_ref.length / 2) as usize)
            };

            let dll_name = from_wide(name_slice);
            println!("Module: {}", dll_name);
            if dll_name.to_lowercase().contains("kernelbase") {
                kernelbase_base = Some(base);
            }else if dll_name.to_lowercase().contains("ntdll") {
                ntdll_base = Some(base);
            }
        }
        // Gå till nästa post i listan
        entry = unsafe { (*entry).flink };

        // Om vi är tillbaka vid början, avsluta loopen
        if entry == list_head {
            break;
        }
    }

    (ntdll_base, kernelbase_base)
}

/* --- Hämta LoadLibrary --- */

#[repr(C)]
struct IMAGE_DOS_HEADER {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [u16; 4],
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [u16; 10],
    e_lfanew: i32,
}

#[repr(C)]
struct IMAGE_NT_HEADERS {
    signature: u32,
    file_header: IMAGE_FILE_HEADER,
    optional_header: IMAGE_OPTIONAL_HEADER,
}

#[repr(C)]
struct IMAGE_FILE_HEADER {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[repr(C)]
struct IMAGE_OPTIONAL_HEADER {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64, // 64-bit for PE32+
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
    data_directory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
struct IMAGE_DATA_DIRECTORY {
    virtual_address: u32,
    size: u32,
}

#[repr(C)]
struct IMAGE_EXPORT_DIRECTORY {
    characteristics: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    name: u32,
    base: u32,
    number_of_functions: u32,
    number_of_names: u32,
    address_of_functions: u32,
    address_of_names: u32,
    address_of_name_ordinals: u32,
}

/* --- MessageBoxA --- */
type MessageBoxA = unsafe extern "system" fn(*mut u8, *const i8, *const i8, u32) -> i32;

fn call_message_box(message_box_addr: *mut u8) {
    unsafe {
        let message_box: MessageBoxA = core::mem::transmute(message_box_addr);
        let caption = std::ffi::CString::new("Hello").unwrap();
        let message = std::ffi::CString::new("World").unwrap();
        message_box(core::ptr::null_mut(), message.as_ptr(), caption.as_ptr(), 0);
    }
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
#[warn(unused_variables)]
pub extern "system" fn WinMain(
    _hInstance: *mut core::ffi::c_void,
    _hPrevInstance: *mut core::ffi::c_void,
    _lpCmdLine: *const u8,
    _nCmdShow: i32,
) -> i32 {
    // Get the base addresses of ntdll.dll and kernelbase.dll
    let (ntdll_base, kernelbase_base) = get_module_bases();

    // Ensure we always have valid pointers (convert None to NULL)
    let ntdll_base = ntdll_base.unwrap_or(std::ptr::null_mut());
    let kernelbase_base = kernelbase_base.unwrap_or(core::ptr::null_mut());

    // Locate the address of LoadLibraryA within kernelbase.dll
    let load_library = match resolve_function(kernelbase_base, "LoadLibraryA")  {
        Some(addr) => {
            println!("LoadLibraryA address: {:?}", addr);
            addr
        }
        None => {
            println!("Failed to find LoadLibraryA");
            return 0;
        }
    };

    // Använd LoadLibraryA för att ladda en DLL (User32 för MessageBoxA)
    let dll_path = "user32.dll";
    let dll_handle = call_load_library(load_library, dll_path);
    if !dll_handle.is_null() {
        println!("Loaded {} at {:?}", dll_path, dll_handle);
    } else {
        println!("Failed to load {}", dll_path);
    }

    // Anropar MessageBoxA från user32.dll
    let dll_handle = call_load_library(load_library, dll_path);
    if !dll_handle.is_null() {
        println!("Dll loaded {} at {:?}", dll_path, dll_handle);

        // Hitta MessageBoxA
        let message_box = match resolve_function(dll_handle, "MessageBoxA")  {
            Some(addr) => {
                println!("MessageBoxA address: {:?}", addr);
                addr
            }
            None => {
                println!("Failed to find MessageBoxA");
                return 0;
            }
        };

        // Anropa MessageBoxA
        call_message_box(message_box);

        return 0;
    } else {
        println!("Failed to load {}", dll_path);
        return 0;
    }
}

/* --- PE Helpers ---*/

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
fn resolve_function(module_base: *mut u8, func_name: &str) -> Option<*mut u8> {
    unsafe {
        let dos_header = module_base as *const IMAGE_DOS_HEADER;
        let nt_headers_addr = (module_base as usize).wrapping_add((*dos_header).e_lfanew as usize);
        let nt_headers = nt_headers_addr as *const IMAGE_NT_HEADERS;

        let export_dir = &(*nt_headers).optional_header.data_directory[0];
        if export_dir.virtual_address == 0 || export_dir.size == 0 {
            #[cfg(debug_assertions)]
            println!("No export directory found");
            return None;
        }

        let export_table_addr = (module_base as usize).wrapping_add(export_dir.virtual_address as usize);
        if export_table_addr % 4 != 0 {
            #[cfg(debug_assertions)]
            println!("Misaligned export table address: {:x}", export_table_addr);
            return None;
        }
        let export_table = export_table_addr as *const IMAGE_EXPORT_DIRECTORY;

        let number_of_names = (*export_table).number_of_names;
        if number_of_names == 0 {
            #[cfg(debug_assertions)]
            println!("No exported names");
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
    println!("{} not found", func_name);
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
fn validate_pe(module_base: *mut u8) -> bool {
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
unsafe fn validate_dos_header(dos_header: *const IMAGE_DOS_HEADER) -> bool {
    if dos_header.is_null() {
        #[cfg(debug_assertions)]
        println!("Null DOS header pointer");
        return false;
    }

    let magic = unsafe { (*dos_header).e_magic };
    if magic == 0x5A4D {
        return true;
    }

    #[cfg(debug_assertions)]
    println!("Invalid DOS magic");
    false
}

/// Validates the e_lfanew field, ensuring it is within a reasonable range and properly aligned for NT headers.
///
/// ## Parameters
/// - `e_lfanew`: The offset (in bytes) from the beginning of the file to the start of the NT headers.
///
/// ## Returns
/// Returns `true` if the e_lfanew is valid and properly aligned, otherwise `false`.
unsafe fn validate_e_lfanew(e_lfanew: i32) -> bool {
    // Se till att e_lfanew är positiv och inom rimligt intervall
    if e_lfanew < 0x40 || e_lfanew > 0x1000 {
        #[cfg(debug_assertions)]
        println!("Invalid e_lfanew: {}", e_lfanew);
        return false;
    }
    // Kontrollera 4-byte alignment
    if e_lfanew % 4 != 0 {
        #[cfg(debug_assertions)]
        println!("Misaligned e_lfanew: {}", e_lfanew);
        return false;
    }
    true
}

/// Validates the PE signature by checking for "PE" (0x4550) to confirm the correct position in the file.
///
/// ## Parameters
/// - `nt_headers`: A pointer to the `IMAGE_NT_HEADERS` structure to validate.
///
/// ## Returns
/// Returns `true` if the PE signature is valid, otherwise `false`.
unsafe fn validate_pe_signature(nt_headers: *const IMAGE_NT_HEADERS) -> bool {
    if nt_headers.is_null() {
        #[cfg(debug_assertions)]
        println!("Null NT headers");
        return false;
    }
    unsafe {
        if (*nt_headers).signature != 0x4550 {
            #[cfg(debug_assertions)]
            println!("Invalid PE signature");
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
unsafe fn validate_pe64(nt_headers : *const IMAGE_NT_HEADERS) -> bool {
    if nt_headers.is_null(){
        #[cfg(debug_assertions)]
        println!("Null NT headers");
        return false;
    }
    unsafe {
        return (*nt_headers).optional_header.magic == 0x20B;
    }
}

/*-- Use LoadLibrary ---*/
type LoadLibraryA = unsafe extern "system" fn(*const i8) -> *mut u8;

fn call_load_library(load_library_addr: *mut u8, dll_path: &str) -> *mut u8 {
    unsafe {
        let load_library: LoadLibraryA = core::mem::transmute(load_library_addr);
        let dll_path_c = std::ffi::CString::new(dll_path).unwrap();
        load_library(dll_path_c.as_ptr())
    }
}

/* --- Helpers ---*/
fn from_wide(slice: &[u16]) -> String {
    String::from_utf16(slice).unwrap_or_default()
}