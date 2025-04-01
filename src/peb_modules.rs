use std::arch::asm;
use crate::{helpers};

#[repr(C)]
struct LIST_ENTRY {
    flink: *mut LIST_ENTRY,
    blink: *mut LIST_ENTRY,
}

#[repr(C)]
struct LDR_DATA_TABLE_ENTRY {
    in_load_order_links: LIST_ENTRY,
    in_memory_order_links: LIST_ENTRY,
    in_initialization_order_links: LIST_ENTRY,
    dll_base: *mut u8,
    entry_point: *mut u8,
    size_of_image: u32,
    full_dll_name: helpers::UNICODE_STRING,
    base_dll_name: helpers::UNICODE_STRING,
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

            let dll_name = helpers::from_wide(name_slice);
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

// Get PEB from TEB, Thank you, Mario
fn get_peb() -> *mut PEB {
    unsafe {
        let teb: *mut TEB;
        unsafe {
            asm!("mov {}, gs:[0x30]", out(reg) teb);
        }
        (*teb).process_environment_block
    }
}
