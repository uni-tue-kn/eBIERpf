// Normal modular-bitfield has wrong bit ordering for network
use modular_bitfield_msb::{bitfield, prelude::{B1, B14, B16, B2, B20, B3, B4, B6, B8}};
use core::mem;

// Declaration similar to network_types
pub const BIER_ETHERTYPE: u16 = 0xAB37_u16.to_be();

pub const BIER_HEADER_SIZE: usize = size_of::<BierHdr>();

// Header according to: https://datatracker.ietf.org/doc/html/rfc8296
//      0                   1                   2                   3
//      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |              BIFT-id                  | TC  |S|     TTL       |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |Nibble |  Ver  |  BSL  |              Entropy                  |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |OAM|Rsv|    DSCP   |   Proto   |            BFIR-id            |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |                BitString  (first 32 bits)                     ~
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     ~                                                               ~
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     ~                BitString  (last 32 bits)                      |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// IMPORTANT FOR BSL:
//       1: 64 bits
//       2: 128 bits
//       3: 256 bits
//       4: 512 bits
//       5: 1024 bits
//       6: 2048 bits
//       7: 4096 bits

// Proto field is based on: https://www.iana.org/assignments/bier/bier.xhtml

#[bitfield]
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub struct Word0 {
    pub bift_id: B20,
    pub tc: B3,
    pub s: B1,
    pub ttl: B8,
}

#[bitfield]
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub struct Word1 {
    pub nibble: B4,
    pub version: B4,
    pub bsl: B4,
    pub entropy: B20,
}

#[bitfield]
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub struct Word2 {
    pub oam: B2,
    pub rsv: B2,
    pub dscp: B6,
    pub proto: B6,
    pub bfir_id: B16,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct BierHdr {
    pub word0: Word0,
    pub word1: Word1,
    pub word2: Word2,
    pub bitstring: [u8; 32], // 256 bits (four 32-bit words)
}

fn reverse_bits_in_bytes(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        *byte = byte.reverse_bits();
    }
}

fn swap_4B_in_byte(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        *byte = (*byte).rotate_right(4);
    }
}


impl BierHdr {
    /// Create a new BierHdr with default values
    pub fn new() -> Self {
        Self {
            word0: Word0::new(),
            word1: Word1::new(),
            word2: Word2::new(),
            bitstring: [0; 32],
        }
    }

     pub fn into_bytes(self) -> [u8; 44] {
        let mut buf = [0u8; 44];

        // Serialize each 32-bit word
        // Problem: The bits are misordered!
        buf[0..4].copy_from_slice(&self.word0.into_bytes());

        buf[4..8].copy_from_slice(&self.word1.into_bytes());
        buf[8..12].copy_from_slice(&self.word2.into_bytes());

        // Serialize the 256-bit bitstring
        buf[12..44].copy_from_slice(&self.bitstring);

        buf
    }

    // Word0 getters and setters
    
    /// Get the BIFT-id field (20 bits)
    pub fn bift_id(&self) -> u32 {
        self.word0.bift_id()
    }
    
    /// Set the BIFT-id field (20 bits)
    pub fn set_bift_id(&mut self, value: u32) {
        self.word0.set_bift_id(value);
    }
    
    /// Get the TC (Traffic Class) field (3 bits)
    pub fn tc(&self) -> u8 {
        self.word0.tc()
    }
    
    /// Set the TC (Traffic Class) field (3 bits)
    pub fn set_tc(&mut self, value: u8) {
        self.word0.set_tc(value);
    }
    
    /// Get the S (Stack) field (1 bit)
    pub fn s(&self) -> bool {
        self.word0.s() == 1
    }
    
    /// Set the S (Stack) field (1 bit)
    pub fn set_s(&mut self, value: bool) {
        self.word0.set_s(value as u8);
    }
    
    /// Get the TTL field (8 bits)
    pub fn ttl(&self) -> u8 {
        self.word0.ttl()
    }
    
    /// Set the TTL field (8 bits)
    pub fn set_ttl(&mut self, value: u8) {
        self.word0.set_ttl(value);
    }

    // Word1 getters and setters
    
    /// Get the Nibble field (4 bits)
    pub fn nibble(&self) -> u8 {
        self.word1.nibble()
    }
    
    /// Set the Nibble field (4 bits)
    pub fn set_nibble(&mut self, value: u8) {
        self.word1.set_nibble(value);
    }
    
    /// Get the Version field (4 bits)
    pub fn version(&self) -> u8 {
        self.word1.version()
    }
    
    /// Set the Version field (4 bits)
    pub fn set_version(&mut self, value: u8) {
        self.word1.set_version(value);
    }
    
    /// Get the BSL (BitString Length) field (4 bits)
    pub fn bsl(&self) -> u8 {
        self.word1.bsl()
    }
    
    /// Set the BSL (BitString Length) field (4 bits)
    pub fn set_bsl(&mut self, value: u8) {
        self.word1.set_bsl(value);
    }
    
    /// Get the Entropy field (20 bits)
    pub fn entropy(&self) -> u32 {
        self.word1.entropy()
    }
    
    /// Set the Entropy field (20 bits)
    pub fn set_entropy(&mut self, value: u32) {
        self.word1.set_entropy(value);
    }

    // Word2 getters and setters
    
    /// Get the OAM field (2 bits)
    pub fn oam(&self) -> u8 {
        self.word2.oam()
    }
    
    /// Set the OAM field (2 bits)
    pub fn set_oam(&mut self, value: u8) {
        self.word2.set_oam(value);
    }
    
    /// Get the Reserved field (2 bits)
    pub fn rsv(&self) -> u8 {
        self.word2.rsv()
    }
    
    /// Set the Reserved field (2 bits)
    pub fn set_rsv(&mut self, value: u8) {
        self.word2.set_rsv(value);
    }
    
    /// Get the DSCP field (6 bits)
    pub fn dscp(&self) -> u8 {
        self.word2.dscp()
    }
    
    /// Set the DSCP field (6 bits)
    pub fn set_dscp(&mut self, value: u8) {
        self.word2.set_dscp(value);
    }
    
    /// Get the Protocol field (6 bits)
    pub fn proto(&self) -> u8 {
        self.word2.proto()
    }
    
    /// Set the Protocol field (6 bits)
    pub fn set_proto(&mut self, value: u8) {
        self.word2.set_proto(value);
    }
    
    /// Get the BFIR-id field (16 bits)
    pub fn bfir_id(&self) -> u16 {
        self.word2.bfir_id()
    }
    
    /// Set the BFIR-id field (16 bits)
    pub fn set_bfir_id(&mut self, value: u16) {
        self.word2.set_bfir_id(value);
    }

    // BitString getters and setters
    
    /// Get the BitString as a byte array
    pub fn bitstring(&self) -> [u8; 32] {
        self.bitstring
    }
    
    /// Set the BitString from a byte array
    pub fn set_bitstring(&mut self, value: [u8; 32]) {
        self.bitstring = value;
    }
    
    /// Get a specific bit from the BitString
    pub fn get_bit(&self, bit_index: usize) -> bool {
        if bit_index >= 256 {
            return false;
        }
        let byte_index = bit_index / 8;
        let bit_offset = bit_index % 8;
        (self.bitstring[byte_index] & (1 << (7 - bit_offset))) != 0
    }
    
    /// Set a specific bit in the BitString
    pub fn set_bit(&mut self, bit_index: usize, value: bool) {
        if bit_index >= 256 {
            return;
        }
        let byte_index = bit_index / 8;
        let bit_offset = bit_index % 8;
        let mask = 1 << (7 - bit_offset);
        
        if value {
            self.bitstring[byte_index] |= mask;
        } else {
            self.bitstring[byte_index] &= !mask;
        }
    }
}

impl Default for BierHdr {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bier_hdr_creation() {
        let hdr = BierHdr::new();
        assert_eq!(hdr.bift_id(), 0);
        assert_eq!(hdr.tc(), 0);
        assert_eq!(hdr.s(), false);
        assert_eq!(hdr.ttl(), 0);
    }

    #[test]
    fn test_word0_fields() {
        let mut hdr = BierHdr::new();
        
        // Test BIFT-id (20 bits, max value = 2^20 - 1 = 1,048,575)
        hdr.set_bift_id(1048575);
        assert_eq!(hdr.bift_id(), 1048575);
        
        // Test TC (3 bits, max value = 7)
        hdr.set_tc(7);
        assert_eq!(hdr.tc(), 7);
        
        // Test S bit
        hdr.set_s(true);
        assert_eq!(hdr.s(), true);
        
        // Test TTL (8 bits, max value = 255)
        hdr.set_ttl(255);
        assert_eq!(hdr.ttl(), 255);
    }

    #[test]
    fn test_word1_fields() {
        let mut hdr = BierHdr::new();
        
        // Test Nibble (4 bits, max value = 15)
        hdr.set_nibble(15);
        assert_eq!(hdr.nibble(), 15);
        
        // Test Version (4 bits, max value = 15)
        hdr.set_version(15);
        assert_eq!(hdr.version(), 15);
        
        // Test BSL (4 bits, max value = 15)
        hdr.set_bsl(15);
        assert_eq!(hdr.bsl(), 15);
        
        // Test Entropy (20 bits, max value = 1,048,575)
        hdr.set_entropy(1048575);
        assert_eq!(hdr.entropy(), 1048575);
    }

    #[test]
    fn test_word2_fields() {
        let mut hdr = BierHdr::new();
        
        // Test OAM (2 bits, max value = 3)
        hdr.set_oam(3);
        assert_eq!(hdr.oam(), 3);
        
        // Test Reserved (2 bits, max value = 3)
        hdr.set_rsv(3);
        assert_eq!(hdr.rsv(), 3);
        
        // Test DSCP (6 bits, max value = 63)
        hdr.set_dscp(63);
        assert_eq!(hdr.dscp(), 63);
        
        // Test Protocol (6 bits, max value = 63)
        hdr.set_proto(63);
        assert_eq!(hdr.proto(), 63);
        
        // Test BFIR-id (16 bits, max value = 65,535)
        hdr.set_bfir_id(65535);
        assert_eq!(hdr.bfir_id(), 65535);
    }

    #[test]
    fn test_bitstring_operations() {
        let mut hdr = BierHdr::new();
        
        // Test setting and getting the entire bitstring
        let test_bitstring = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        hdr.set_bitstring(test_bitstring);
        assert_eq!(hdr.bitstring(), test_bitstring);
        
        // Test individual bit operations
        hdr.set_bit(0, true);
        assert_eq!(hdr.get_bit(0), true);
        
        hdr.set_bit(0, false);
        assert_eq!(hdr.get_bit(0), false);
        
        hdr.set_bit(63, true);
        assert_eq!(hdr.get_bit(63), true);
    }
}
