from scapy.all import *
from scapy.packet import Packet, bind_layers
from scapy.fields import BitField, ByteField, ShortField, IntField, XIntField, FieldLenField, StrFixedLenField

import time
from random import choice

addr4 = [
    "230.40.50.60",
    "239.1.1.1"
#  "230.40.50.60",
#  "239.1.1.1",
#  "232.100.200.1",
#  "233.33.44.55",
#  "238.8.8.8",
]

addr6 = [
  "ff3e::1",
  "ff3e::abcd",
  "ff3e::2:2",
  "ff05::1234",
  "ff3e::ffff"
]

while True:
    time.sleep(0.05)

    addr_4_choice = choice(addr4)
    
    # Build packet: Ethernet / BIER / IP / UDP
    pkt = (
        Ether(dst="02:42:ac:11:00:02", src="02:42:ac:11:00:01", type=0x0800) /
        IP(dst=addr_4_choice, src="192.168.0.1") /
        UDP(sport=12345, dport=54321) /
        Raw(load="Hello via BIER")
    )

    # Send the packet on interface (adjust iface name)
    sendp(pkt, iface="lo", verbose=True)
    