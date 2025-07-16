use std::{fs::File, io::BufReader, net::IpAddr, u64};

use anyhow::Context;
use aya::{
    maps::{HashMap, MapData},
    Ebpf, EbpfLoader,
};
use bier_common::bier::BIER_HEADER_SIZE;
use log::{debug, warn};

use crate::{
    config::{BierConfig, BierMapping},
    tui::RowData,
};

pub struct Mappings {
    data: BierConfig,
    v4: HashMap<MapData, u32, [u8; BIER_HEADER_SIZE]>,
    v6: HashMap<MapData, u128, [u8; BIER_HEADER_SIZE]>,
    v4_ingress: HashMap<MapData, u32, u64>,
    v4_egress: HashMap<MapData, u32, u64>,
    v6_ingress: HashMap<MapData, u128, u64>,
    v6_egress: HashMap<MapData, u128, u64>,
    pub ebpf: Ebpf,
}

impl Mappings {
    fn load_ebpf(name: &str, local: &[u8; 32]) -> anyhow::Result<Ebpf> {
        // Bump the memlock rlimit. This is needed for older kernels that don't use the
        // new memcg based accounting, see https://lwn.net/Articles/837122/
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 {
            debug!("remove limit on locked memory failed, ret is: {ret}");
        }

        // This will include your eBPF object file as raw bytes at compile-time and load it at
        // runtime. This approach is recommended for most real-world use cases. If you would
        // like to specify the eBPF program at runtime rather than at compile-time, you can
        // reach for `Bpf::load_file` instead.
        let mut ebpf = EbpfLoader::new()
            .set_global("LOCAL_BFER", local, true)
            .load(aya::include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/bier"
            )))?;
        if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }

        Ok(ebpf)
    }
    pub fn from_file(file: &str, program: &str) -> anyhow::Result<Mappings> {
        let data: BierConfig = serde_json::from_reader(BufReader::new(File::open(file)?))?;

        let mut ebpf = Mappings::load_ebpf(program, &data.local)?;

        // Main maps for mapping IP to BIER
        let v4: HashMap<_, u32, [u8; BIER_HEADER_SIZE]> =
            HashMap::try_from(ebpf.take_map("IPMC4_TO_BIER").unwrap())?;
        let v6: HashMap<_, u128, [u8; BIER_HEADER_SIZE]> =
            HashMap::try_from(ebpf.take_map("IPMC6_TO_BIER").unwrap())?;

        // Packet counters based on address
        // -- IPv4
        let v4_ingress: HashMap<_, u32, u64> =
            HashMap::try_from(ebpf.take_map("v4_INGRESS_COUNTER").unwrap())?;
        let v4_egress: HashMap<_, u32, u64> =
            HashMap::try_from(ebpf.take_map("v4_EGRESS_COUNTER").unwrap())?;
        // -- IPv6
        let v6_ingress: HashMap<_, u128, u64> =
            HashMap::try_from(ebpf.take_map("v6_INGRESS_COUNTER").unwrap())?;
        let v6_egress: HashMap<_, u128, u64> =
            HashMap::try_from(ebpf.take_map("v6_EGRESS_COUNTER").unwrap())?;

        Ok(Mappings {
            data,
            v4,
            v6,
            v4_ingress,
            v4_egress,
            v6_ingress,
            v6_egress,
            ebpf,
        })
    }

    pub fn write_config(&mut self) -> anyhow::Result<()> {
        for (addr, hdr) in self.data.entries.iter() {
            match addr {
                IpAddr::V4(data) => {
                    let num: u32 = u32::from_be_bytes(data.octets());
                    self.v4
                        .insert(num, hdr.to_bier_hdr()?.into_bytes(), 0)
                        .context("Failed insertion of IPv4 HashMap entry!")?;

                    // Initialize counter!
                    self.v4_egress.insert(num, 0, 0)?;
                }
                IpAddr::V6(data) => {
                    let num: u128 = u128::from_be_bytes(data.octets());
                    self.v6
                        .insert(num, hdr.to_bier_hdr()?.into_bytes(), 0)
                        .context("Failed insertion of IPv6 HashMap entry!")?;

                    self.v6_egress.insert(num, 0, 0)?;
                }
            }
        }
        Ok(())
    }

    pub fn get_data(&self) -> Vec<RowData> {
        let mut data: Vec<RowData> = Vec::new();

        data.push(RowData {
            ipmc_group: "local BFER".to_string(),
            packet_count: 0,
            bitstring: self
                .data
                .local
                .iter()
                .map(|byte| format!("{:x}", byte))
                .collect::<Vec<String>>()
                .join("."),
        });

        for (addr, hdr) in self.data.entries.iter() {
            let addr_str = addr.to_string();

            let bit_header = hdr.to_bier_hdr();

            if let Ok(hdr) = bit_header {
                let bs: String = hdr
                    .bitstring()
                    .iter()
                    .map(|byte| format!("{:x}", byte))
                    .collect::<Vec<String>>()
                    .join(".");

                let packet_count = match addr {
                    IpAddr::V4(v4_addr) => {
                        let num: u32 = u32::from_be_bytes(v4_addr.octets());
                        let count: u64 = self.v4_egress.get(&num, 0).unwrap_or(u64::MAX);
                        count
                    }
                    IpAddr::V6(v6_addr) => {
                        let num: u128 = u128::from_be_bytes(v6_addr.octets());
                        let count: u64 = self.v6_egress.get(&num, 0).unwrap_or(u64::MAX);
                        count
                    }
                };

                data.push(RowData {
                    ipmc_group: addr_str,
                    packet_count,
                    bitstring: bs, // 256 bits
                });
            }
        }

        data
    }

    pub fn get_header_fields(&self, addr: IpAddr) -> Vec<String> {
        if let Some(hdr) = self.data.entries.get(&addr) {
            hdr.to_string_vec()
        } else {
            Vec::new()
        }
    }

    pub fn get_local(&self) -> [u8; 32] {
        self.data.local
    }
}
