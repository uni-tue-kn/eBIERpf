use core::mem::offset_of;

use aya_ebpf::{
    bindings::{bpf_cmd::BPF_MAP_UPDATE_ELEM, TC_ACT_OK},
    helpers::r#gen::{bpf_map_lookup_elem, bpf_skb_change_head, bpf_skb_store_bytes},
    macros::map,
    maps::{HashMap, PerCpuArray},
    memcpy,
    programs::TcContext,
};
use aya_log_ebpf::{info, warn};
use network_types::{
    eth::{self, EtherType},
    ip::Ipv4Hdr,
};

use bier_common::bier::{self, BierHdr, BIER_ETHERTYPE, BIER_HEADER_SIZE};

use crate::{util::{ptr_at, tc_ptr_at, tc_ptr_mut_at, EthHdr}, NUM_CPUS};

#[map]
static IPMC4_TO_BIER: HashMap<u32, [u8; BIER_HEADER_SIZE]> =
    HashMap::<u32, [u8; BIER_HEADER_SIZE]>::with_max_entries(1024, 0);
#[map]
static IPMC6_TO_BIER: HashMap<u128, [u8; BIER_HEADER_SIZE]> =
    HashMap::<u128, [u8; BIER_HEADER_SIZE]>::with_max_entries(1024, 0);

#[map]
static mut v4_EGRESS_COUNTER: HashMap<u32, u64> = HashMap::<u32, u64>::with_max_entries(1024, 0);
#[map]
static mut v6_EGRESS_COUNTER: HashMap<u128, u64> = HashMap::<u128, u64>::with_max_entries(1024, 0);

#[inline(always)]
pub fn process_egress(ctx: TcContext) -> Result<i32, ()> {
    // Get memory offset to ethertype field of ethhdr
    let ethertype_offset = offset_of!(EthHdr, ether_type);

    // Get ethertype over memory offset, error leads to go to next action and skip processing
    let ethertype = u16::from_be(ctx.load(ethertype_offset).map_err(|_| ())?);

    // TODO: add IPv6 handling
    if ethertype != 0x0800 {
        info!(&ctx, "Passed non IP packet: {}", ethertype);
        return Ok(TC_ACT_OK);
    }

    let ipv4hdr: *const Ipv4Hdr = tc_ptr_at(&ctx, EthHdr::LEN)?;

    // Perform lookup in MC Group Map
    let addr = unsafe { u32::from_be_bytes((*ipv4hdr).dst_addr) };

    if let Some(bier_hdr) = IPMC4_TO_BIER.get_ptr_mut(&addr) {
        info!(&ctx, "Found mapping for address {}", addr);

        

        // Push BIER header, adjust ethertype accordingly

        // Grow packet size
        let ret = unsafe { bpf_skb_change_head(ctx.skb.skb, BIER_HEADER_SIZE as u32, 0) };

        // TODO ret value handling

        // Move Eth header to new front
        {
            // Old eth header, now moved back by BIER header size
            let ethhdr: *mut EthHdr = tc_ptr_mut_at(&ctx, BIER_HEADER_SIZE)?;

            // New eth header, at offset zero
            let new_ethhdr: *mut EthHdr = tc_ptr_mut_at(&ctx, 0)?;

            // Copy old eth header to new location in packet, change ethertype
            unsafe {
                memcpy(new_ethhdr as *mut _, ethhdr as *mut _, EthHdr::LEN);
                (*new_ethhdr).ether_type = BIER_ETHERTYPE;
            }
        }

        // Write new BIER header
        let bier_hdr_start: *mut [u8; BIER_HEADER_SIZE] = tc_ptr_mut_at(&ctx, EthHdr::LEN)?;
        unsafe {
            memcpy(
                bier_hdr_start as *mut _,
                bier_hdr as *mut _,
                BIER_HEADER_SIZE,
            );
        }

        info!(&ctx, "Adding BIER successfull!");

        // Update counter for this mapping
        if let Some(entry_ptr) = unsafe {v4_EGRESS_COUNTER.get_ptr_mut(&addr)} {
            // TODO: how bad can this screw up? This is probably not atomic?
            unsafe {
                (*entry_ptr) += 1;
            }
        } else {
            warn!(&ctx, "Could not increment counter for: {}! Map not initialized yet?",addr);
        }

    }

    Ok(TC_ACT_OK)
}
