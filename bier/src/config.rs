use std::{collections::HashMap, net::IpAddr};

use anyhow::Error;
use bier_common::bier::{BierHdr, Word0, Word1, Word2};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// TODO: bit limitatiosn check?
#[derive(Serialize,Deserialize,Debug)]
pub struct SerdeBierHdr {
    pub bift_id: u32, // 20 bits
    pub tc: u8,       // 3 bits
    pub s: bool,      // 1 bit
    pub ttl: u8,      // 8 bits
    pub nibble: u8,   // 4 bits
    pub version: u8,  // 4 bits
    pub bsl: u8,      // 4 bits
    pub entropy: u32, // 20 bits
    pub oam: u8,      // 2 bits
    pub rsv: u8,      // 2 bits
    pub dscp: u8,     // 6 bits
    pub proto: u8,    // 6 bits
    pub bfir_id: u16, // 16 bits
    pub bitstring: [u8; 32] // 256 bits
}

pub type BierMapping = HashMap<IpAddr, SerdeBierHdr>;


#[derive(Serialize,Deserialize,Debug)]
pub struct BierConfig {
    pub local: [u8; 32],
    pub entries: BierMapping
}


impl SerdeBierHdr {
    pub fn to_bier_hdr(&self) -> anyhow::Result<BierHdr> {

        let word0 = Word0::new()
            .with_bift_id_checked(self.bift_id).map_err(|e| anyhow::Error::msg(e.to_string()))?
            .with_tc_checked(self.tc).map_err(|e| anyhow::Error::msg(e.to_string()))?
            .with_s_checked(self.s as u8 ).map_err(|e| anyhow::Error::msg(e.to_string()))?
            .with_ttl_checked(self.ttl).map_err(|e| anyhow::Error::msg(e.to_string()))?;

        let word1: Word1 = Word1::new()
            .with_nibble_checked(self.nibble).map_err(|e| anyhow::Error::msg(e.to_string()))?
            .with_version_checked(self.version).map_err(|e| anyhow::Error::msg(e.to_string()))?
            .with_bsl_checked(self.bsl).map_err(|e| anyhow::Error::msg(e.to_string()))?
            .with_entropy_checked(self.entropy).map_err(|e| anyhow::Error::msg(e.to_string()))?;

        let word2 = Word2::new()
            .with_oam_checked(self.oam).map_err(|e| anyhow::Error::msg(e.to_string()))?
            .with_rsv_checked(self.rsv).map_err(|e| anyhow::Error::msg(e.to_string()))?
            .with_dscp_checked(self.dscp).map_err(|e| anyhow::Error::msg(e.to_string()))?
            .with_proto_checked(self.proto).map_err(|e| anyhow::Error::msg(e.to_string()))?
            .with_bfir_id_checked(self.bfir_id).map_err(|e| anyhow::Error::msg(e.to_string()))?;

        let hdr = BierHdr{
            word0,
            word1,word2,
            bitstring: self.bitstring
        };
        Ok(hdr)
    }

    pub fn to_string_vec(&self) -> Vec<String> {
        let json: Value = serde_json::to_value(self).unwrap();
        json.as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| format!("{}: {}", k, v))
            .collect()
    }
}

