#![no_main]
#![no_std]
#![allow(clippy::unusual_byte_groupings)]
#![feature(ptr_metadata)]
#![feature(asm_experimental_arch)]
#![feature(naked_functions)]


use core::hint::black_box;
use core::mem::{size_of, transmute};
use core::ptr::{from_raw_parts, from_raw_parts_mut};

use n64::aes::{decrypt, set_key_iv};
use n64::boot::launch_app;
use n64::card::{CardStatus, BYTES_PER_BLOCK, BYTES_PER_PAGE, PAGES_PER_BLOCK};
use n64::mi::mi;
use n64::pi::{pi, LedValue};
use n64::ri::ri;
use n64::si::si;
use n64::text::Colour;
use n64::usb::{usb0, usb1};
use n64::util::{k0_to_phys_u32, phys_to_k1_u32};
use n64::v2::virage2;
use n64::vi::vi;
use n64::{block_to_page, data_cache_invalidate};

extern crate n64;

mod skc;

fn dram_init() {
    let ri = ri();

    ri.set_bb_mode(1 << 31);
    ri.bb_mode();

    ri.set_bb_mode((1 << 13) | (1 << 1));
    ri.bb_mode();

    ri.set_bb_mode(1 << 8);
    ri.bb_mode();

    ri.set_bb_mode(1 << 31);
    ri.bb_mode();

    ri.set_bb_mode(1 << 30);
    ri.bb_mode();

    ri.set_bb_mode(1 << 30);
    ri.bb_mode();

    ri.set_bb_mode((3 << 4) | (1 << 3) | (2 << 0));
    ri.bb_mode();

    ri.set_unknown(0x40, 0x031111E4);
    ri.unknown(0x30);
    ri.unknown(0x30);

    ri.set_unknown(0x60, 1);
    ri.unknown(0x30);

    ri.set_unknown(0x80, 1);
    ri.unknown(0x30);

    for _ in 0..100 {
        ri.unknown(0x30);
    }

    ri.set_unknown(0x30, 0x000011E0);
    ri.unknown(0x30);
}

fn find_next_good_block(after: u16) -> Result<u16, ()> {
    let pi = pi();

    let mut block = after;

    loop {
        if pi.read_page(block_to_page!(block)) == CardStatus::DoubleBitError {
            return Err(());
        }

        let block_status = pi.spare0(4);

        let num_bad_bits = (block_status | 0xFF00FFFF).count_zeros();

        if num_bad_bits < 2 {
            break;
        }

        block += 1;
    }

    Ok(block)
}

fn block_link(spare: u32) -> u8 {
    let a = (spare >> 8) as u8;
    let b = (spare >> 16) as u8;
    let c = (spare >> 24) as u8;
    if a == b {
        a
    } else {
        c
    }
}

static mut CMD_BUF: [u8; BYTES_PER_BLOCK] = [0xAA; BYTES_PER_BLOCK];

fn load_sa_ticket(after: u16) -> Result<u16, ()> {
    let pi = pi();

    let ticket_block = find_next_good_block(after)?;

    let mut start_block = 0;

    for i in 0..PAGES_PER_BLOCK {
        if pi.read_page(block_to_page!(ticket_block) + i) != CardStatus::Ok {
            return Err(());
        }

        if i == 0 {
            start_block = block_link(pi.spare0(0)) as u16;
        }

        for j in (0..BYTES_PER_PAGE).step_by(size_of::<u32>()) {
            unsafe {
                CMD_BUF[(i * BYTES_PER_PAGE + j) as usize
                    ..(i * BYTES_PER_PAGE + j) as usize + size_of::<u32>()]
                    .copy_from_slice(&pi.buffer0(j).to_be_bytes());
            }
        }
    }

    Ok(start_block)
}

fn load_page(
    page: u32,
    continuation: bool,
    dram_addr: &mut u32,
    length: u32,
    first: bool,
) -> Result<(), ()> {
    let pi = pi();

    if pi.read_page(page) != CardStatus::Ok {
        return Err(());
    }

    pi.run_aes(continuation);

    pi.aes_wait();

    if first {
        *dram_addr = pi.buffer0(8);
    }

    if *dram_addr != 0 {
        let slc = unsafe {
            core::slice::from_raw_parts_mut(
                *dram_addr as *mut u8,
                BYTES_PER_PAGE.min(length) as usize,
            )
        };

        pi.bb_read_into(slc, 0);
    }

    Ok(())
}

fn set_proc_permissions(permissions: u32) {
    let pi = pi();
    pi.set_bb_allowed_io(permissions & 0xFF);

    let usb0 = usb0();
    let usb1 = usb1();

    usb0.set_sec_mode((permissions >> 8) & 1);
    usb1.set_sec_mode((permissions >> 8) & 1);

    let mi = mi();

    let val = mi.bb_secure_exception() & !(1 << 24);
    mi.set_bb_secure_exception(val | (if permissions & (1 << 9) != 0 { 1 } else { 0 } << 24));
}

fn load_system_app() -> Result<u32, ()> {
    let pi = pi();
    let si = si();

    let mut sa1_start = load_sa_ticket(4)?;

    let mut sa1_key = [0xAA; 16];
    unsafe {
        decrypt(
            &CMD_BUF[0x9C..0xAC],
            &mut sa1_key,
            virage2.read().boot_app_key,
            CMD_BUF[0x14..0x24].try_into().unwrap(),
        );
    }

    /*vi().print_u32(
        2,
        2,
        Colour::WHITE,
        u32::from_be_bytes(sa1_key[0..4].try_into().unwrap()),
    );
    vi().print_u32(
        11,
        2,
        Colour::WHITE,
        u32::from_be_bytes(sa1_key[4..8].try_into().unwrap()),
    );
    vi().print_u32(
        20,
        2,
        Colour::WHITE,
        u32::from_be_bytes(sa1_key[8..12].try_into().unwrap()),
    );
    vi().print_u32(
        29,
        2,
        Colour::WHITE,
        u32::from_be_bytes(sa1_key[12..16].try_into().unwrap()),
    );
    vi().next_framebuffer();*/

    //loop {}

    //si.txrx(&sa1_key, None);

    let size = u32::from_be_bytes(unsafe { CMD_BUF }[0x0C..0x10].try_into().unwrap());
    let sa1_end_page = size.div_ceil(BYTES_PER_PAGE);

    set_key_iv(&sa1_key, &unsafe { CMD_BUF }[0x38..0x48]);

    let mut dram_addr = 0;

    let mut continuation = false;

    let mut length = BYTES_PER_PAGE;

    for page in 0..(0x1000 / BYTES_PER_PAGE) {
        load_page(
            block_to_page!(sa1_start) + page,
            continuation,
            &mut dram_addr,
            length,
            page == 0,
        )?;

        continuation = true;
    }

    let entrypoint = dram_addr;

    let mut remaining = size;

    let mut page = 0x1000 / BYTES_PER_PAGE;

    for j in (0x1000 / BYTES_PER_PAGE)..sa1_end_page {
        if remaining > BYTES_PER_PAGE {
            length = BYTES_PER_PAGE;
            remaining -= BYTES_PER_PAGE;
        } else {
            length = remaining;
            remaining = 0;
        }

        load_page(
            block_to_page!(sa1_start) + page,
            continuation,
            &mut dram_addr,
            length,
            false,
        )?;

        page += 1;

        if page >= PAGES_PER_BLOCK {
            page = 0;
            sa1_start = block_link(pi.spare0(0)) as u16;
        }

        dram_addr += length;
    }

    let permissions = u32::from_be_bytes(unsafe { CMD_BUF }[0x4C..0x50].try_into().unwrap());
    set_proc_permissions(permissions);

    Ok(entrypoint)
}

#[no_mangle]
fn main() -> ! {
    let pi = pi();
    let mi = mi();
    let vi = vi();
    let si = si();

    pi.power_on();
    mi.set_bb_mask(0b00_00_00_01__00_00_00_00__00_00_00_00__00_00_00_00); // clear BTN interrupt
    mi.set_bb_secure_exception(mi.bb_secure_exception() & !(1 << 25)); // disable BTN trap
    mi.set_bb_secure_timer(0);
    pi.set_status((1 << 1) | (1 << 0)); // clear PI interrupt, reset DMA controller
    pi.set_bb_nand_ctrl(0);
    pi.set_bb_aes_ctrl(0);
    vi.set_v_current(0); // clear VI interrupt
    unsafe {
        from_raw_parts_mut::<u32>(phys_to_k1_u32(0x04040010) as *mut (), ())
            .write_volatile((1 << 15) | (1 << 3));
        from_raw_parts_mut::<u32>(phys_to_k1_u32(0x0450000C) as *mut (), ()).write_volatile(0);
        // clear AI interrupt
    };
    si.set_status(0); // clear SI interrupt
    mi.set_mode(1 << 11); // clear DP interrupt
    mi.set_mask(0b00_00_00_00__00_00_00_00__00_00_01_01__01_01_01_01); // disable SP, SI, AI, CI, PI and DP interrupts
    mi.set_bb_mask(0b00_00_01_01__01_01_01_01__01_01_00_00__00_00_00_00); // disable BB interrupts

    if mi.bb_secure_exception() & 0xFC == 0 {
        // cold boot
        dram_init();

        vi.pll_init();
        /*vi.init_calibrate();
        vi.init();*/
    } else {
        /*vi.init();*/
    }

    //vi.clear_framebuffer();

    pi.init_hw();
    /*si.init_hw();
    si.txrx(b"Test string", None);*/

    let address = load_system_app().expect("failed to load SA");

    pi.set_led(LedValue::Off);

    let address = address as *const ();

    let entry = unsafe { transmute::<*const (), unsafe extern "C" fn(u32) -> !>(address) };

    unsafe { launch_app(entry) }
}

#[no_mangle]
fn check_trial_timer() {
    mi().set_bb_secure_timer(0);
    //unsafe { (0xA0000000 as *mut u32).write_volatile(mi().bb_secure_timer()) };
}
