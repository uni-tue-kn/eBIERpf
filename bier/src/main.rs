// Load config from files
// TODO: interface to change during runtime
pub mod config;
// TUI for user interface
pub mod tui;
// Meta structure that stores mappings
pub mod mapping;

use std::{
    fs::File,
    io::BufReader,
    net::{IpAddr, Ipv4Addr},
};

use anyhow::Context;
use aya::{
    maps::{HashMap, MapData, PerCpuArray},
    programs::{tc, SchedClassifier, TcAttachType, Xdp, XdpFlags}, EbpfLoader,
};
use bier_common::bier::{BierHdr, BIER_HEADER_SIZE};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

use crate::{config::BierMapping, mapping::Mappings, tui::run_tui};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "lo")]
    iface: String,
    #[clap(short, long, default_value = "config.json")]
    config: String
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    let Opt { iface, config } = opt;

    // Get config
    let mut mappings = Mappings::from_file(&config, "bier").context("Failed loading Mappings!")?;


    // --- XDP init, ingress
    let xdp: &mut Xdp = mappings.ebpf.program_mut("bier_ingress").unwrap().try_into()?;
    xdp.load()?;
    xdp.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    // -- TC init, egress
    let _ = tc::qdisc_add_clsact(&iface);
    let tc: &mut SchedClassifier = mappings.ebpf.program_mut("bier_egress").unwrap().try_into()?;
    tc.load()?;
    tc.attach(&iface, TcAttachType::Egress)?;

    // -- Write egress IPMC to BIER map  
    mappings.write_config().context("Failed writing mappings to data plane!")?;

    // ebpf remains alive and loaded here!
    let _ = run_tui(mappings);

    Ok(())
}
