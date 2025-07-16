#![no_std]
#![no_main]

pub mod util;
pub mod ingress;
pub mod egress;

const NUM_CPUS: usize = 16;

use aya_ebpf::{
    bindings::{xdp_action, TC_ACT_OK},
    macros::{classifier, xdp},
    programs::{TcContext, XdpContext},
};

use crate::{egress::process_egress, ingress::process_ingress};

#[classifier]
pub fn bier_egress(ctx: TcContext) -> i32 {
    match process_egress(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK,
    }
}

#[xdp]
pub fn bier_ingress(ctx: XdpContext) -> u32 {
    match process_ingress(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
