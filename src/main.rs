#![no_main]
#![no_std]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use core::panic::PanicInfo;
use core::ptr;

mod peb_modules;
mod pe_helper;
mod helpers;
mod win_api;
mod types;
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

        // Locate the address of NtCreateFile within ntdll.dll
        let ntcreatefile = match pe_helper::resolve_function(NT_DLL_BASE, "NtCreateFile") {
            Some(addr) => addr,
            None => return -1,
        };
        // Create a file using  NtCreateFile
        let status = create_file(ntcreatefile, NT_DLL_BASE);
        if status != 0 {
            return status; // Return NTSTATUS if we fail
        }


        // Anropar MessageBoxA från user32.dll
        let dll_path: &[u8] = b"user32.dll\0";
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

/*-- Use LoadLibrary ---*/
type LoadLibraryA = unsafe extern "system" fn(*const i8) -> *mut u8;

fn call_load_library(load_library_addr: *mut u8, dll_path: &[u8]) -> *mut u8 {
    unsafe {
        let load_library: LoadLibraryA = core::mem::transmute(load_library_addr);
        load_library(dll_path.as_ptr() as *const i8)
    }
}

/* -- NtCreateFile -- */
// Konstanter för NtCreateFile
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const FILE_SHARE_READ: u32 = 0x1;
const FILE_SHARE_WRITE: u32 = 0x2;
const FILE_CREATE: u32 = 0x2;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
const GENERIC_READ: u32 = 0x80000000;
const GENERIC_WRITE: u32 = 0x40000000;
const SYNCHRONIZE: u32 = 0x00100000;

// Structs för NtCreateFile

#[repr(C)]
struct OBJECT_ATTRIBUTES {
    length: u32,
    root_directory: *mut u8,
    object_name: *mut types::UNICODE_STRING,
    attributes: u32,
    security_descriptor: *mut u8,
    security_quality_of_service: *mut u8,
}

#[repr(C)]
struct IO_STATUS_BLOCK {
    status: i32, // NTSTATUS
    information: usize,
}

type NtCreateFile = unsafe extern "system" fn(
    *mut *mut u8,           // FileHandle
    u32,                    // DesiredAccess
    *mut OBJECT_ATTRIBUTES, // ObjectAttributes
    *mut IO_STATUS_BLOCK,   // IoStatusBlock
    *mut i64,               // AllocationSize
    u32,                    // FileAttributes
    u32,                    // ShareAccess
    u32,                    // CreateDisposition
    u32,                    // CreateOptions
    *mut u8,                // EaBuffer
    u32,                    // EaLength
) -> i32; // NTSTATUS

fn create_file(ntcreatefile_addr: *mut u8, ntdll_base: *mut u8) -> i32 {
    unsafe {
        let ntcreatefile: NtCreateFile = core::mem::transmute(ntcreatefile_addr);

        // Filename as UTF-16: "\??\C:\test.txt"
        static FILE_PATH: &[u16] = &[
            b'\\' as u16, b'?' as u16, b'?' as u16, b'\\' as u16,
            b'C' as u16, b':' as u16, b'\\' as u16,
            b't' as u16, b'e' as u16, b's' as u16, b't' as u16,
            b'.' as u16, b't' as u16, b'x' as u16, b't' as u16, 0u16
        ];

        // Sätt upp UNICODE_STRING
        let mut unicode_string = types::UNICODE_STRING {
            length: (FILE_PATH.len() - 1) as u16 * 2, // Längd i bytes, exkl. null
            maximum_length: FILE_PATH.len() as u16 * 2,
            buffer: FILE_PATH.as_ptr() as *mut u16,
        };

        // Sätt upp OBJECT_ATTRIBUTES
        let mut object_attributes = OBJECT_ATTRIBUTES {
            length: core::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            root_directory: core::ptr::null_mut(),
            object_name: &mut unicode_string,
            attributes: 0x40, // OBJ_CASE_INSENSITIVE
            security_descriptor: core::ptr::null_mut(),
            security_quality_of_service: core::ptr::null_mut(),
        };

        // Sätt upp IO_STATUS_BLOCK
        let mut io_status_block = IO_STATUS_BLOCK {
            status: 0,
            information: 0,
        };

        let mut file_handle: *mut u8 = core::ptr::null_mut();

        // Call NtCreateFile
        let status = ntcreatefile(
            &mut file_handle,                          // FileHandle
            GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, // DesiredAccess
            &mut object_attributes,                    // ObjectAttributes
            &mut io_status_block,                      // IoStatusBlock
            core::ptr::null_mut(),                     // AllocationSize
            FILE_ATTRIBUTE_NORMAL,                     // FileAttributes
            FILE_SHARE_READ | FILE_SHARE_WRITE,        // ShareAccess
            FILE_CREATE,                               // CreateDisposition
            FILE_SYNCHRONOUS_IO_NONALERT,              // CreateOptions
            core::ptr::null_mut(),                     // EaBuffer
            0,                                         // EaLength
        );

        // Om det lyckades (status == 0), stäng handtaget (vi behöver inte det)
        if status == 0 {
            // ToDo
            // Vi skulle kunna använda NtClose från ntdll.dll för att stänga handtaget,
            // men för enkelhetens skull skippar vi det i denna PoC.
        }

        status
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

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}