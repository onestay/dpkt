from . import dpkt


class DCCP(dpkt.Packet):
    __hdr__ = (
        ("sport", "H", 0),
        ("dport", "H", 0),
        ("_offset", "B", 0),
        ("_ccval_cscov", "B", 0),
        ("checksum", "H", 0),
        ("_res_type_x", "B", 0),
    )

    class DCCPRequest(dpkt.Packet):
        __hdr__ = (("code", "B", 0),)

        def unpack(self, buf):
            dpkt.Packet.unpack(self, buf)

    __bit_fields__ = {
        "_ccval_cscov": (("ccval", 4), ("cscov", 4)),
        "_res_type_x": (("_res", 3), ("type", 4), ("x", 1)),
    }

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)

        # when Extended Sequence Numbers (X) is set to 1, seqeuence numbers take up 48 bytes
        if self.x == 1:
            self.seq = buf[self.__hdr_len__ + 1 : self.__hdr_len__ + 7]
            self.__hdr_len__ += 6
        else:
            self.seq = buf[self.__hdr_len__ : self.__hdr_len__ + 4]
            self.__hdr_len__ += 3
        self.data = buf[self.__hdr_len__ + 1:]
        self.data = self.DCCPRequest(self.data)
        setattr(self, self.data.__class__.__name__.lower(), self.data)

    def __len__(self):
        return len(bytes(self))


def test_dccp_unpack_request():
    data = (
        b"\xd9\x91\x14\x51\x12\x00\xe8\xfb\x01\x00\x5f\x34\x7b\x1c\x28\x2c"
        b"\x00\x00\x00\x00\x00\x00\x2e\x0b\x01\xac\xd6\xf7\x86\xe7\xf4\xb2"
        b"\x15\x2e\x07\x0c\x00\x00\x00\x00\x29\x06\x16\xfc\x49\x08\x20\x06"
        b"\x01\x02\x03\x05\x22\x06\x01\x02\x03\x05\x01\x20\x04\x02\x00\x01"
        b"\x20\x04\x04\x01\x22\x04\x0a\x00"
    )

    dccp = DCCP(data)
    assert dccp.sport == 55697
    assert dccp.dport == 5201
    assert dccp.ccval == 0
    assert dccp.cscov == 0
    assert dccp.checksum == 0xE8FB
    assert dccp.type == 0
    assert dccp.x == 1
    assert dccp.seq == b"\x5f\x34\x7b\x1c\x28\x2c"
    assert dccp.data.code == 0
