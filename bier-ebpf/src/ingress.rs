use aya_ebpf::bindings::TC_ACT_SHOT;
use aya_ebpf::cty::c_int;
use aya_ebpf::helpers::r#gen::bpf_xdp_adjust_head;
use aya_ebpf::macros::map;
use aya_ebpf::maps::{HashMap, PerCpuArray};
use aya_ebpf::memcpy;
use aya_ebpf::{bindings::xdp_action, programs::XdpContext};
use aya_log_ebpf::{error, info};
use network_types::eth::{EthHdr, EtherType};

use bier_common::bier::{BierHdr, BIER_ETHERTYPE, BIER_HEADER_SIZE};

use crate::util::{ptr_at, ptr_mut_at};
use crate::NUM_CPUS;

#[map]
static mut v4_INGRESS_COUNTER: HashMap<u32, u64> = HashMap::<u32, u64>::with_max_entries(1024, 0);
#[map]
static mut v6_INGRESS_COUNTER: HashMap<u128, u64> = HashMap::<u128, u64>::with_max_entries(1024, 0);


#[no_mangle]
// Bit for BFER in indexed byte
static mut LOCAL_BFER: [u8; 32] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];

#[inline(always)]
pub fn process_ingress(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *mut EthHdr = ptr_mut_at(&ctx, 0)?;
    let ethertype = unsafe { (*ethhdr).ether_type as u16 };

    // Continue only if BIER packet
    if ethertype != BIER_ETHERTYPE {
        info!(&ctx, "Passed non-BIER packet: {}", ethertype);
        return Ok(xdp_action::XDP_PASS);
    }

    // Packet is BIER, check BFER bit to remove BIER
    //let bier_hdr: *const BierHdr = ptr_at(&ctx, EthHdr::LEN)?;


    // Iterate over bytes in BIER bitstring
    let mut bit_match: bool = false;
    for i in 0..32 {
        let bs_byte: *const u8 = ptr_mut_at(&ctx, EthHdr::LEN + i)?;
        if unsafe {
            (*bs_byte) & LOCAL_BFER[i] > 0
        } {
            bit_match = true;
            break;
        }
    }

    if !bit_match {
        error!(&ctx,"No BFER bit match, dropping packet!"); 
        return  Err(());
    }

    // Get new start location of ethernet header (shifted right by size of BIER header)
    let new_ethhdr: *mut EthHdr = ptr_mut_at(&ctx, BIER_HEADER_SIZE)?;

    // Copy old eth header to new location in packet
    unsafe {
        memcpy(new_ethhdr as *mut _, ethhdr as *mut _, EthHdr::LEN);
    }

    // Adjust ethertype back to IPv4
    // TODO: needs mapping based on BIER Next header fields!
    unsafe {
        (*new_ethhdr).ether_type = EtherType::Ipv4;
    }

    // Move head back to start of new eth header
    // Delta is size of removed header
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, BIER_HEADER_SIZE as i32) } != 0 {
        error!(&ctx, "Failed to adjust XDP head! Dropping.");
        return Err(()); // Causes packet drop in calling func
    }

    info!(&ctx, "Successfully decapsulated BIER packet!");

    Ok(xdp_action::XDP_PASS)
}
