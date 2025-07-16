from scapy.all import *
from scapy.packet import Packet, bind_layers
from scapy.fields import BitField, ByteField, ShortField, IntField, XIntField, FieldLenField, StrFixedLenField

# Define custom BIER Header
class BIER(Packet):
    name = "BIER"
    fields_desc = [
        # Word 1 First 32 bits
        BitField("bift_id", 0, 20),
        BitField("tc", 0, 3),
        BitField("s", 0, 1),
        ByteField("ttl", 20),
        # Word 2 Next 32 bits
        BitField("nibble", 0, 4),     # Usually set to 0x5
        BitField("version", 0, 4),
        BitField("bsl", 3, 4),       # BitString Length: e.g., 64 bits
        BitField("entropy", 0,20),
        # Word 3 Next 32 bits
        BitField("oam", 0, 2),
        BitField("rsv", 0, 2),
        BitField("dscp", 0, 6),
        BitField("proto", 0x11,6),     # 0x11 = UDP
        ShortField("bfir_id", 0),
        # Word 4 32 bits * 8
        BitField("bitstring", 0,256)
    ]

# Bind BIER with Ether (custom ethertype 0xAB37)
bind_layers(Ether, BIER, type=0xAB37)
# Bind BIER with IP
bind_layers(BIER, IP)

# Build packet: Ethernet / BIER / IP / UDP
pkt = (
    Ether(dst="02:42:ac:11:00:02", src="02:42:ac:11:00:01", type=0xAB37) /
    BIER(
        bift_id=0x12345,
        tc=1,
        s=1,
        ttl=64,
        nibble=5,
        version=0,
        bsl=3,
        entropy=0x0FFFFFFF,
        oam=0,
        rsv=0,
        dscp=0,
        proto=4, # IPv4
        bfir_id=0x42,
        bitstring=0
    ) /
    IP(dst="192.168.0.2", src="192.168.0.1") /
    UDP(sport=12345, dport=54321) /
    Raw(load="Hello via BIER")
)

# Send the packet on interface (adjust iface name)
sendp(pkt, iface="lo", verbose=True)
