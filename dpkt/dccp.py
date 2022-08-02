from . import dpkt
import struct


DCCP_PACKAGE_TYPE_REQUEST = 0
DCCP_PACKAGE_TYPE_RESPONSE = 1
DCCP_PACKAGE_TYPE_ACK = 3


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

    class DCCPData(dpkt.Packet):
        pass

    class DCCPAckDataAck(dpkt.Packet):
        def __init__(self, *args, x, **kwargs):
            self.x = x
            self.ack = 0
            super().__init__(*args, **kwargs)
        def unpack(self, buf):
            if self.x == 1:
                # 2 byte header with the first 16 bits reserved and the remaining 48 bits being the ack number
                (low, high) = struct.unpack("!IH", buf[2:])
                self.ack = (low << 16) | high
            else:
                # TODO add case for handling 24 ack
                pass

    __bit_fields__ = {
        "_ccval_cscov": (("ccval", 4), ("cscov", 4)),
        "_res_type_x": (("_res", 3), ("type", 4), ("x", 1)),
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
            # TODO add case for handling 24 bit seq nums
            pass

        self.data = buf[self.__hdr_len__ + 1 :]
        if self.type == DCCP_PACKAGE_TYPE_REQUEST or self.type == DCCP_PACKAGE_TYPE_RESPONSE:
            self.data = self.DCCPRequestResponse(self.data)
        elif self.type == DCCP_PACKAGE_TYPE_ACK:
            self.data = self.DCCPAckDataAck(self.data, x=self.x)

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


def test_dccp_unpack_ack():
    data = (
        b"\x14\x51\x90\x39\x06\x00\x67\xf4\x07\x00\xcd\xe3\xea\xdf\x6d\xcf"
        b"\x00\x00\xa9\x1e\x8a\xb5\x40\x7a"
    )

    dccp = DCCP(data)
    assert dccp.sport == 5201
    assert dccp.dport == 36921
    assert dccp.type == 3
    assert dccp.data.ack == 185948641247354
