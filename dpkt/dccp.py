from . import dpkt
import struct


DCCP_PACKAGE_TYPE_REQUEST = 0
DCCP_PACKAGE_TYPE_RESPONSE = 1


class DCCP(dpkt.Packet):
    __hdr__ = (
        ("sport", "H", 0),
        ("dport", "H", 0),
        ("_offset", "B", 0),
        ("_ccval_cscov", "B", 0),
        ("checksum", "H", 0),
        ("_res_type_x", "B", 0),
    )

    class DCCPRequestResponse(dpkt.Packet):
        __hdr__ = (("code", "B", 0),)

    __bit_fields__ = {
        "_ccval_cscov": (("ccval", 4), ("cscov", 4)),
        "_res_type_x": (("_res", 3), ("type", 4), ("x", 1)),
    }

    _package_types = {
        DCCP_PACKAGE_TYPE_REQUEST: DCCPRequestResponse,
        DCCP_PACKAGE_TYPE_RESPONSE: DCCPRequestResponse,
    }

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)

        # when Extended Sequence Numbers (X) is set to 1, seqeuence numbers take up 48 bytes
        if self.x == 1:
            (low, high) = struct.unpack(
                "!IH", buf[self.__hdr_len__ + 1 : self.__hdr_len__ + 7]
            )
            self.seq = (low << 16) | high
            self.__hdr_len__ += 6
        else:
            self.seq = buf[self.__hdr_len__ : self.__hdr_len__ + 4]
            self.__hdr_len__ += 3
        self.data = buf[self.__hdr_len__ + 1 :]
        self.data = self._package_types[self.type](self.data)
        setattr(self, self.data.__class__.__name__.lower(), self.data)

    def __len__(self):
        return len(bytes(self))


def test_dccp_unpack_request():
    data = (
        b"\x90\x39\x14\x51\x12\x00\xf9\xd2\x01\x00\xa9\x1e\x8a\xb5\x40\x79"
        b"\x00\x00\x00\x00\x00\x2e\x0c\x03\x00\x7e\xa0\xed\x38\x8f\xf7\x9b"
        b"\x0f\x2e\x07\x0c\x00\x00\x00\x00\x29\x06\x11\x00\xc1\x36\x20\x06"
        b"\x01\x02\x03\x05\x22\x06\x01\x02\x03\x05\x01\x20\x04\x02\x00\x01"
        b"\x20\x04\x04\x01\x22\x04\x0a\x00"
    )

    dccp = DCCP(data)
    assert dccp.sport == 36921
    assert dccp.dport == 5201
    assert dccp.ccval == 0
    assert dccp.cscov == 0
    assert dccp.checksum == 0xF9D2
    assert dccp.type == 0
    assert dccp.x == 1
    assert dccp.seq == 185948641247353
    assert dccp.data.code == 0
