-- BIER Wireshark Lua Dissector

local bier_proto = Proto("bierd", "BIER Headerd")

-- Fields
local f = bier_proto.fields
-- Word 1
f.bift_id = ProtoField.uint32("bier.bift_id", "BIFT ID", base.HEX, nil, 0xFFFFF000)
f.tc      = ProtoField.uint32("bier.tc", "Traffic Class", base.DEC, nil, 0x00000E00)
f.s       = ProtoField.uint32("bier.s", "S Bit", base.DEC, nil,          0x00000100)
f.ttl     = ProtoField.uint32("bier.ttl", "TTL", base.DEC, nil,          0x000000FF)

-- Word 2
f.nibble  = ProtoField.uint32("bier.nibble", "Nibble", base.HEX, nil,    0xF0000000)
f.version = ProtoField.uint32("bier.version", "Version", base.DEC, nil,  0x0F000000)
f.bsl     = ProtoField.uint32("bier.bsl", "BSL", base.DEC, nil,          0x00F00000)
f.entropy = ProtoField.uint32("bier.entropy", "Entropy", base.DEC, nil, 0x000FFFFF)

-- Word 3
-- First byte
f.oam     = ProtoField.uint32("bier.oam", "OAM", base.DEC, nil,           0xC0000000)
f.rsv     = ProtoField.uint32("bier.rsv", "Reserved", base.DEC, nil,      0x30000000)
f.dscp    = ProtoField.uint32("bier.dscp", "DSCP", base.DEC, nil,         0x0FC00000)
f.proto   = ProtoField.uint32("bier.proto", "Proto", base.HEX, nil,       0x003F0000)
f.bfir_id = ProtoField.uint32("bier.bfir_id", "BFIR-ID", base.DEC, nil,   0x0000FFFF)

-- Word 4 - 7
f.bitstring = ProtoField.bytes("bier.bitstring", "BitString", base.BIN)

local bier_proto_dissector_table = DissectorTable.new("bier", "BIER Next Protocold", ftypes.UINT8, base.DEC)

function bier_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "BIER"

    if buffer:len() < 16 then return 0 end

    local subtree = tree:add(bier_proto, buffer(), "BIER Header")

    -- Word 1
    local word1_tree = subtree:add(buffer(0, 4), "-----------------------------------------")
    subtree:add(f.bift_id, buffer(0,4))
    subtree:add(f.tc, buffer(0,4))
    subtree:add(f.s, buffer(0,4))
    subtree:add(f.ttl, buffer(0,4))

    -- Word 2
    local word2_tree = subtree:add(buffer(4, 4), "-----------------------------------------")
    subtree:add(f.nibble, buffer(4, 4))
    subtree:add(f.version, buffer(4, 4))
    subtree:add(f.bsl, buffer(4, 4))
    subtree:add(f.entropy, buffer(4, 4))

    -- Word 3
    local word3_tree = subtree:add(buffer(8, 4), "-----------------------------------------")
    subtree:add(f.oam, buffer(8, 4))
    subtree:add(f.rsv, buffer(8, 4))
    subtree:add(f.dscp, buffer(8, 4))
    subtree:add(f.proto, buffer(8, 4))
    subtree:add(f.bfir_id, buffer(8, 4))

    -- Word 4: Bitstring
    local bitstring_tree = subtree:add(buffer(12, 32), "-----------------------------------------")
    subtree:add(f.bitstring, buffer(12, 32))

    -- Next header
    local word3 = buffer(8, 4):uint()
    local proto_val = bit.rshift(bit.band(word3, 0x003F0000), 16)

    -- Pass to next dissector using custom table
    local payload_offset = 44
    if buffer:len() > payload_offset then
        local payload = buffer(payload_offset):tvb()
        bier_proto_dissector_table:try(proto_val, payload, pinfo, tree)
    end

end

-- Bind to ethertype
local ethertype_table = DissectorTable.get("ethertype")
ethertype_table:add(0xAB37, bier_proto)

DissectorTable.get("bier"):add(4, Dissector.get("ip"))               -- IPv4
DissectorTable.get("bier"):add(6, Dissector.get("ipv6"))             -- IPv6
DissectorTable.get("bier"):add(3, Dissector.get("eth_withoutfcs"))  -- ETth
