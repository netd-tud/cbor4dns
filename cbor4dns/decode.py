"""
Provides the decoder for encoding DNS messages to application/dns+cbor
"""

import enum
import struct
from typing import Optional, Union

import cbor2
import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype


class MsgType(enum.Enum):
    QUERY = 0x0
    RESPONSE = 0x1


class Decoder:
    def __init__(self, fp):
        self.fp = fp
        self.cbor_decoder = cbor2.CBORDecoder(fp)

    def _init_msg_type(self, obj, msg_type, flags_default=0):
        offset = 0
        if isinstance(obj[0], int):
            res = msg_type(obj[0])
            offset += 1
            if isinstance(obj[1], int):
                flags = obj[1]
                offset += 1
            else:
                flags = flags_default
        else:
            res = msg_type(0)
            flags = flags_default
        res.flags = flags
        return offset, res

    def _decode_question(self, cbor_question):
        if len(cbor_question) == 1:
            rdclass = dns.rdataclass.IN
            rdtype = dns.rdatatype.AAAA
        elif len(cbor_question) == 2:
            rdclass = dns.rdataclass.IN
            rdtype = cbor_question[1]
        elif len(cbor_question) == 3:
            rdclass = cbor_question[2]
            rdtype = cbor_question[1]
        else:
            raise ValueError(f"Invalid length for question {cbor_question!r}")
        return dns.rrset.RRset(
            name=dns.name.from_text(cbor_question[0]), rdclass=rdclass, rdtype=rdtype
        )

    def _decode_rr(self, name, section, cbor_rr, res):
        if isinstance(cbor_rr, bytes):
            wire_reader = dns.message._WireReader(cbor_rr, lambda msg: None)
            wire_reader.message = dns.message.Message()
            wire_reader._get_section(section, 1)
            if wire_reader.message.opt:
                res.opt = wire_reader.message.opt
            # TODO: tsig
            else:
                res.sections[section].append(wire_reader.message.sections[section][0])
        elif isinstance(cbor_rr, list):
            if len(cbor_rr) < 2 or len(cbor_rr) > 5:
                raise ValueError(f"Resource record of unexpected length")
            if isinstance(cbor_rr[0], int):
                name = name
                ttl = cbor_rr[0]
                offset = 1
            else:
                name = dns.name.from_text(cbor_rr[0])
                ttl = cbor_rr[1]
                offset = 2

            if isinstance(cbor_rr[offset], int):
                rdtype = cbor_rr[offset]
                offset += 1
                if isinstance(cbor_rr[offset], int):
                    rdclass = cbor_rr[offset]
                    offset += 1
                else:
                    rdclass = dns.rdataclass.IN
            else:
                rdtype = dns.rdatatype.AAAA
                rdclass = dns.rdataclass.IN

            rdata = cbor_rr[offset]
            if isinstance(rdata, str):
                rdata = dns.name.from_text(rdata).to_wire()
            elif isinstance(rdata, int):
                # TODO: check if this suffices
                rdata = struct.pack("!l", rdata)
            rrset = dns.rrset.RRset(name, rdclass, rdtype)
            rd = dns.rdata.from_wire(rdclass, rdtype, rdata, 0, len(rdata))
            rrset.add(rd, ttl)
            res.sections[section].append(rrset)
        else:
            raise ValueError(f"Unexpected resource record type for {cbor_rr!r}")

    def decode_query(self, obj: list = None) -> dns.message.QueryMessage:
        if obj is None:
            obj = self.cbor_decoder.decode()
        if not isinstance(obj, list):
            raise ValueError(f"Unexpected query object {obj!r}")
        offset, res = self._init_msg_type(obj, dns.message.QueryMessage)
        sections = len(obj) - offset
        res.question = [self._decode_question(obj[offset])]
        if sections == 1:
            authority = []
            additional = []
        if sections == 2:
            authority = []
            additional = obj[offset + 1]
        elif sections == 3:
            authority = obj[offset + 1]
            additional = obj[offset + 2]
        else:
            raise ValueError(
                f"Unexpected number of sections {sections} in query object {obj!r}"
            )
        name = res.question[0].name
        for rr in authority:
            self._decode_rr(name, dns.message.AUTHORITY, rr, res)
        for rr in additional:
            self._decode_rr(name, dns.message.ADDITIONAL, rr, res)
        return res

    def decode_response(
        self,
        orig_query: Optional[Union[bytes, list]] = None,
        packed: bool = False,
        obj: list = None,
    ) -> dns.message.Message:
        if orig_query is not None:
            if isinstance(orig_query, bytes):
                orig_query = cbor2.decode(orig_query)
            orig_query = self.decode_query(orig_query)
        if obj is None:
            obj = self.cbor_decoder.decode()
        if not isinstance(obj, list):
            raise ValueError(f"Unexpected response object {obj!r}")
        offset, res = self._init_msg_type(obj, dns.message.Message, 0x8000)
        sections = len(obj) - offset
        if sections == 1:
            if orig_query is None:
                raise ValueError(
                    f"No question provided for {obj!r} with orig_question is None"
                )
            res.question = orig_query.question
            answer = obj[offset]
            additional = []
            authority = []
        elif sections <= 4:
            res.question = [self._decode_question(obj[offset])]
            answer = obj[offset + 1]
            additional = []
            authority = []
            if sections == 3:
                authority = obj[offset + 2]
            elif sections == 4:
                additional = obj[offset + 3]
                authority = obj[offset + 2]
        else:
            raise ValueError(
                f"Unexpected number of sections {sections} in response object {obj!r}"
            )
        name = res.question[0].name
        for rr in answer:
            self._decode_rr(name, dns.message.ANSWER, rr, res)
        for rr in authority:
            self._decode_rr(name, dns.message.AUTHORITY, rr, res)
        for rr in additional:
            self._decode_rr(name, dns.message.ADDITIONAL, rr, res)
        return res

    def decode(
        self,
        msg_type: MsgType,
        orig_query: Optional[Union[bytes, list]] = None,
        packed: bool = False,
        obj: list = None,
    ) -> dns.message.Message:
        if msg_type == MsgType.QUERY:
            return self.decode_query(obj=obj)
        elif msg_type == MsgType.RESPONSE:
            return self.decode_response(orig_query=orig_query, packed=packed, obj=obj)
        else:
            raise ValueError(r"Unexpected message type {msg_type!r}")
