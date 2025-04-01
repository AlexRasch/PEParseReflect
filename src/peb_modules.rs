use core::arch::asm;
use crate::{helpers,win_api};

#[repr(C)]
struct LIST_ENTRY {
    flink: *mut LIST_ENTRY,
    blink: *mut LIST_ENTRY,
}

#[repr(C)]
pub struct UNICODE_STRING {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
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

#[repr(C)]
struct PEB_LDR_DATA {
    _pad: [u8; 16],
    in_memory_order_module_list: LIST_ENTRY,
}


pub fn get_module_bases() -> (Option<*mut u8>, Option<*mut u8>) {
    let peb = get_peb();
    let ldr = unsafe { (*peb).ldr };

    if ldr.is_null() {
        //println!("LDR is null");
        return (None, None);
    }

    // Start from first post inside `in_memory_order_module_list`
    let mut entry = unsafe { (*ldr).in_memory_order_module_list.flink };
    let list_head = entry;

    let mut ntdll_base: Option<*mut u8> = None;
    let mut kernelbase_base: Option<*mut u8> = None;

    const NTDLL: &[u16] = &[
        b'n' as u16,
        b't' as u16,
        b'd' as u16,
        b'l' as u16,
        b'l' as u16,
        b'.' as u16,
        b'd' as u16,
        b'l' as u16,
        b'l' as u16,
        0u16
    ];
    const KERNELBASE: &[u16] = &[
        b'K' as u16,
        b'E' as u16,
        b'R' as u16,
        b'N' as u16,
        b'E' as u16,
        b'L' as u16,
        b'B' as u16,
        b'A' as u16,
        b'S' as u16,
        b'E' as u16,
        b'.' as u16,
        b'd' as u16,
        b'l' as u16,
        b'l' as u16,
        0u16
    ];


    while !entry.is_null() {
        let ldr_entry = entry as *mut LDR_DATA_TABLE_ENTRY;
        let base = unsafe { (*ldr_entry).dll_base };
        let name_ref = unsafe { &(*ldr_entry).base_dll_name };

        if !name_ref.buffer.is_null() {

            let name_ptr = name_ref.buffer;

            if unsafe { win_api::lstrcmpiW(name_ptr, NTDLL.as_ptr()) } == 0 {
                ntdll_base = Some(base);
            } else if unsafe { win_api::lstrcmpiW(name_ptr, KERNELBASE.as_ptr()) } == 0 {
                kernelbase_base = Some(base);
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

// Get PEB from TEB, Thank you, Mario
fn get_peb() -> *mut PEB {
    unsafe {
        let teb: *mut TEB;
        asm!("mov {}, gs:[0x30]", out(reg) teb);
        (*teb).process_environment_block
    }
}
