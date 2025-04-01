#![no_main]
//#![no_std]

use core::arch::asm;
use core::ptr;
use core::slice;

mod pe_helper;

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
        return (None, None);
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
            } else if dll_name.to_lowercase().contains("ntdll") {
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
    unsafe {
        // Get the base addresses of ntdll.dll and kernelbase.dll
        let (ntdll_base, kernelbase_base) = get_module_bases();

        // Ensure we always have valid pointers (convert None to NULL)
        let ntdll_base = ntdll_base.unwrap_or(std::ptr::null_mut());
        let kernelbase_base = kernelbase_base.unwrap_or(core::ptr::null_mut());

        // Locate the address of LoadLibraryA within kernelbase.dll
        let load_library = match pe_helper::resolve_function(kernelbase_base, "LoadLibraryA") {
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
            let message_box = match pe_helper::resolve_function(dll_handle, "MessageBoxA") {
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
