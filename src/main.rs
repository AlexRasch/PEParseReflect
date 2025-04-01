#![no_main]
#![no_std]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use core::panic::PanicInfo;
use core::ptr;

mod peb_modules;
mod pe_helper;
mod helpers;
mod win_api;
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

/*-- Use LoadLibrary ---*/
type LoadLibraryA = unsafe extern "system" fn(*const i8) -> *mut u8;

fn call_load_library(load_library_addr: *mut u8, dll_path: &[u8]) -> *mut u8 {
    unsafe {
        let load_library: LoadLibraryA = core::mem::transmute(load_library_addr);
        load_library(dll_path.as_ptr() as *const i8)
    }
}


/* --- MessageBoxA --- */
type MessageBoxA = unsafe extern "system" fn(*mut u8, *const i8, *const i8, u32) -> i32;

fn call_message_box(message_box_addr: *mut u8) {
    unsafe {
        let message_box: MessageBoxA = core::mem::transmute(message_box_addr);
        static CAPTION: &[u8] = b"Hello\0";
        static MESSAGE: &[u8] = b"World\0";
        message_box(core::ptr::null_mut(),
                    MESSAGE.as_ptr() as *const i8,
                    CAPTION.as_ptr() as *const i8,
                    0
        );
    }
}

static mut KERNEL_BASE: *mut u8 = ptr::null_mut();
static mut NT_DLL_BASE: *mut u8 = ptr::null_mut();


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
        let (ntdll_base, kernelbase_base) = peb_modules::get_module_bases();

        // Ensure we always have valid pointers (convert None to NULL)
        NT_DLL_BASE = ntdll_base.unwrap_or(core::ptr::null_mut());
        KERNEL_BASE = kernelbase_base.unwrap_or(core::ptr::null_mut());



        // Locate the address of LoadLibraryA within kernelbase.dll
        let load_library = match pe_helper::resolve_function(KERNEL_BASE, "LoadLibraryA") {
            Some(addr) => {
                //println!("LoadLibraryA address: {:?}", addr);
                addr
            }
            None => {
                //println!("Failed to find LoadLibraryA");
                return 0;
            }
        };

        // Använd LoadLibraryA för att ladda en DLL (User32 för MessageBoxA)
        let dll_path: &[u8] = b"user32.dll\0";
        let dll_handle = call_load_library(load_library, dll_path);
        if !dll_handle.is_null() {
            //println!("Loaded {} at {:?}", dll_path, dll_handle);
        } else {
            //println!("Failed to load {}", dll_path);
        }

        // Anropar MessageBoxA från user32.dll
        let dll_handle = call_load_library(load_library, dll_path);
        if !dll_handle.is_null() {
            //println!("Dll loaded {} at {:?}", dll_path, dll_handle);

            // Hitta MessageBoxA
            let message_box = match pe_helper::resolve_function(dll_handle, "MessageBoxA") {
                Some(addr) => {
                    //println!("MessageBoxA address: {:?}", addr);
                    addr
                }
                None => {
                    //println!("Failed to find MessageBoxA");
                    return 0;
                }
            };

            // Anropa MessageBoxA
            call_message_box(message_box);

            return 0;
        } else {
            //println!("Failed to load {}", dll_path);
            return 0;
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}