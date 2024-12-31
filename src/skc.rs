use core::arch::asm;
use core::mem::{transmute, MaybeUninit};

use n64::aes;
use n64::boot::launch_app;
use n64::mi::mi;
use n64::pi::pi;
use n64::text::Colour;
use n64::types::*;
use n64::v2::virage2;
use n64::vi::vi;

use crate::set_proc_permissions;

type SKCTableEntry = extern "C" fn() -> i32;

#[no_mangle]
pub static SKC_TABLE: [SKCTableEntry; 22] = unsafe {
    [
        transmute::<extern "C" fn(Option<&mut Id>) -> i32, SKCTableEntry>(get_id), // this is fine :)
        transmute::<
            extern "C" fn(
                Option<&TicketBundle>,
                Option<&AppLaunchCrls>,
                Option<&mut RecryptList>,
            ) -> i32,
            SKCTableEntry,
        >(launch_setup),
        transmute::<extern "C" fn(unsafe extern "C" fn(u32) -> !) -> !, SKCTableEntry>(launch),
        dummy_skc,
        dummy_skc,
        dummy_skc,
        dummy_skc,
        dummy_skc,
        dummy_skc,
        transmute::<
            extern "C" fn(
                Option<&[u8; 20]>,
                Option<&[u8; 256]>,
                Option<&[Option<&[u8; 0x390]>; 5]>,
                Option<&[*const u8; 3]>,
            ) -> i32,
            SKCTableEntry,
        >(verify_hash),
        transmute::<extern "C" fn(Option<&mut u16>, Option<&mut u16>) -> i32, SKCTableEntry>(
            get_consumption,
        ),
        advance_ticket_window,
        transmute::<extern "C" fn(u16, u16) -> i32, SKCTableEntry>(set_limit),
        dummy_skc,
        keep_alive,
        // debug
        dummy_skc,
        dummy_skc,
        dummy_skc,
        dummy_skc,
        dummy_skc,
        dummy_skc, // custom
        dummy_skc,
    ]
};

#[no_mangle]
pub static SKC_TABLE_SIZE: usize = SKC_TABLE.len();

static mut LAUNCH_CMD_HEAD: ContentMetaDataHead = ContentMetaDataHead {
    unused_padding: 0,
    ca_crl_version: 0,
    cp_crl_version: 0,
    size: 0,
    desc_flags: 0,
    common_cmd_iv: [0; 16],
    hash: [0; 20],
    iv: [0; 16],
    exec_flags: 0,
    hw_access_rights: 0,
    secure_kernel_rights: 0,
    bbid: 0,
    issuer: [0; 64],
    id: 0,
    key: [0; 16],
    content_meta_data_sign: [0; 256],
};
static mut LAUNCH_KEY: AesKey = [0; 16];

fn load_ticket(ticket: &Ticket) -> i32 {
    let cmd_head = &ticket.cmd.head;
    let ticket_head = &ticket.head;

    unsafe { LAUNCH_CMD_HEAD = *cmd_head };

    // should generate ecc key
    let ecc_key = AesKey::default();

    let mut first_layer = AesKey::default();

    aes::decrypt(&cmd_head.key, &mut first_layer, ecc_key, ticket_head.cmd_iv);
    aes::decrypt(
        &first_layer,
        &mut unsafe { LAUNCH_KEY },
        unsafe { virage2.read() }.boot_app_key,
        cmd_head.common_cmd_iv,
    );

    0
}

extern "C" fn get_id(out_bbid: Option<&mut Id>) -> i32 {
    if let Some(out) = out_bbid {
        *out = unsafe { virage2.read() }.bbid;
    }

    0
}

extern "C" fn launch_setup(
    bundle: Option<&TicketBundle>,
    _crls: Option<&AppLaunchCrls>,
    recrypt_list: Option<&mut RecryptList>,
) -> i32 {
    let Some(bundle) = bundle else {
        return 1;
    };

    let Some(ticket) = bundle.ticket else {
        return 1;
    };

    if load_ticket(ticket) != 0 {
        return 1;
    }

    if unsafe { LAUNCH_CMD_HEAD }.exec_flags & 2 != 0 {
        // needs recrypt

        let Some(list) = recrypt_list else {
            return 1;
        };

        let (key, state) = list.get_key_for_cid(unsafe { LAUNCH_CMD_HEAD }.id);
        if state != RecryptState::Finished {
            return state as i32;
        }

        aes::set_key_iv(&key, &unsafe { LAUNCH_CMD_HEAD }.iv);
    } else {
        aes::set_key_iv(&unsafe { LAUNCH_KEY }, &unsafe { LAUNCH_CMD_HEAD }.iv);
    }

    0
}

extern "C" fn launch(entrypoint: unsafe extern "C" fn(u32) -> !) -> ! {
    set_proc_permissions(unsafe { LAUNCH_CMD_HEAD }.hw_access_rights);

    if pi().bb_gpio() & 0xC0000000 != 0 {
        mi().set_bb_mask(0b00_00_00_01__00_00_00_00__00_00_00_00__00_00_00_00);
        mi().set_bb_mask(0b00_00_00_10__00_00_00_00__00_00_00_00__00_00_00_00);
        mi().set_bb_secure_exception(mi().bb_secure_exception() | (1 << 25));
    }

    unsafe { launch_app(entrypoint) }
}

extern "C" fn verify_hash(
    _hash: Option<&ShaHash>,
    _sig: Option<&[u8; 256]>,
    _cert_chain: Option<&[Option<&[u8; 0x390]>; 5]>,
    _crls: Option<&[*const u8; 3]>,
) -> i32 {
    0 // always return true
}

extern "C" fn get_consumption(tid_window: Option<&mut u16>, cc: Option<&mut u16>) -> i32 {
    if let Some(window) = tid_window {
        *window = 0;
    }

    if let Some(cc) = cc {
        *cc = 0;
    }

    0
}

extern "C" fn advance_ticket_window() -> i32 {
    0 // do nothing
}

extern "C" fn set_limit(_limit: u16, _code: u16) -> i32 {
    0 // do nothing
}

extern "C" fn keep_alive() -> i32 {
    0 // do nothing
}

extern "C" fn dummy_skc() -> i32 {
    let num: u32;
    unsafe { asm!("",out("$2") num) } // bad bad bad way to get skc number

    let vi = vi();

    vi.init();
    vi.clear_framebuffer();

    loop {
        vi.clear_framebuffer();

        vi.print_string(2, 2, Colour::RED, "Unhandled SKC 0x  ");
        vi.print_u8(18, 2, Colour::GREEN, num as _);

        vi.wait_vsync();
        vi.next_framebuffer();
    }
}
