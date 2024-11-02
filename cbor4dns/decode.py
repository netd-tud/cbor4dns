"""
Provides the decoder for encoding DNS messages to application/dns+cbor
"""

import contextlib
import enum
import struct
from typing import Optional, Union, Tuple

import cbor2
import dns.edns
import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.OPT

from . import utils


class MsgType(enum.Enum):
    QUERY = 0x0
    RESPONSE = 0x1


class DerefType(enum.Enum):
    NONE = 0x0
    VALUE = 0x1
    STRAIGHT = 0x2
    INVERTED = 0x3


class Decoder:
    def __init__(self, fp):
        self.fp = fp
        self.cbor_decoder = cbor2.CBORDecoder(fp)
        self.packing_table = None
        self._ref_idx = None

    @classmethod
    def is_ref(cls, obj):
        if isinstance(obj, cbor2.CBORSimpleValue):
            return 0 <= obj.value <= 15
        if isinstance(obj, cbor2.CBORTag):
            return (
                obj.tag == 6
                or 216 <= obj.tag <= 255
                or 27647 <= obj <= 28671
                or 28704 <= obj <= 32767
                or 1811940352 <= obj <= 1879048191
                or 1879052288 <= obj <= 2147483647
            )
        return False

    def ref_to_type_and_idx(self, obj) -> Tuple[DerefType, int]:
        if isinstance(obj, cbor2.CBORSimpleValue):
            if 0 <= obj.value <= 15:
                deref_type = DerefType.VALUE
                idx = obj.value
            else:
                return DerefType.NONE, 0
        elif isinstance(obj, cbor2.CBORTag):
            if obj.tag == 6:
                if isinstance(obj.value, int):
                    deref_type = DerefType.VALUE
                    if obj.value >= 0:
                        idx = 16 + (2 * obj.value)
                    else:
                        idx = 16 - (2 * obj.value) - 1
                else:
                    deref_type = DerefType.STRAIGHT
                    idx = 0
            elif 216 <= obj.tag <= 223:
                deref_type = DerefType.INVERTED
                idx = obj.tag - 216
            elif 224 <= obj.tag <= 255:
                deref_type = DerefType.STRAIGHT
                idx = obj.tag - 224
            elif 27647 <= obj.tag <= 28671:
                deref_type = DerefType.INVERTED
                idx = obj.tag - 27647 + 8
            elif 28704 <= obj.tag <= 32767:
                deref_type = DerefType.STRAIGHT
                idx = obj.tag - 28704 + 32
            elif 1811940352 <= obj.tag <= 1879048191:
                deref_type = DerefType.INVERTED
                idx = obj.tag - 1811940352 + 1024
            elif 1879052288 <= obj.tag <= 2147483647:
                deref_type = DerefType.STRAIGHT
                idx = obj.tag - 1879052288 + 4096
            else:
                return DerefType.NONE, 0
        else:
            return DerefType.NONE, 0
        if not isinstance(self.packing_table, list):
            raise ValueError(f"No packing table found for {obj!r}")
        if idx < 0 or idx >= len(self.packing_table):
            raise IndexError(
                f"Packing table {self.packing_table} too short for {obj!r}"
                f"(index = {idx})"
            )
        return deref_type, idx

    def deref(self, obj):
        if self.packing_table is None:
            # don't have a packing table, just deref as object
            return obj
        deref_type, idx = self.ref_to_type_and_idx(obj)
        if deref_type == DerefType.VALUE:
            return self.packing_table[idx]
        elif deref_type == DerefType.STRAIGHT:
            assert isinstance(obj, cbor2.CBORTag)
            return self.packing_table[idx] + obj.value
        elif deref_type == DerefType.INVERTED:
            assert isinstance(obj, cbor2.CBORTag)
            return obj.value + self.packing_table[idx]
        else:
            # not a reference
            return obj

    def _unpack_packing_table(self):
        if not isinstance(self.packing_table, list):
            return
        # skip for empty packing table
        ref_in_packing_table = len(self.packing_table) > 0
        iterations = 0
        while ref_in_packing_table and iterations < len(self.packing_table):
            iterations += 1
            ref_in_packing_table = False
            for cur_idx in range(len(self.packing_table)):
                deref_type, ref_idx = self.ref_to_type_and_idx(
                    self.packing_table[cur_idx]
                )
                if deref_type == DerefType.NONE:
                    continue
                if self.is_ref(self.packing_table[ref_idx]):
                    # referenced item is a reference as well, need to repeat iteration
                    ref_in_packing_table = True
                    continue
                self.packing_table[cur_idx] = self.deref(self.packing_table[cur_idx])
        if ref_in_packing_table:
            raise ValueError(
                "Potentially circular references detected in packing table "
                f"{self.packing_table}"
            )

    def _init_msg_type(self, obj, msg_type, flags_default=0):
        offset = 0
        obj[0] = self.deref(obj[0])
        if isinstance(obj[0], int):
            flags = obj[0]
            offset += 1
        else:
            flags = flags_default
        res = msg_type(0)
        res.flags = flags
        return offset, res

    @staticmethod
    def _is_name(element):
        is_str = isinstance(element, str)
        is_ref_tag = (
            isinstance(element, cbor2.CBORTag) and element.tag == utils.RefIdx.tag
        )
        if is_ref_tag:
            ref = element.value
        else:
            ref = None
        return is_str or is_ref_tag, ref

    def _decode_name(self, array):
        offset = 0
        name = ""
        is_name, ref = self._is_name(array[offset])
        ref_idx_start = len(self._ref_idx)
        while is_name:
            if ref is None:  # array[offset] is a string
                self._ref_idx.append([array[offset]])
                for ref_idx in self._ref_idx[ref_idx_start:-1]:
                    ref_idx.append(array[offset])
                name = f"{name}.{self.deref(array[offset])}"
            else:
                suffix = self._ref_idx[ref]
                for ref_idx in self._ref_idx[ref_idx_start:]:
                    ref_idx.extend(suffix)
                name = f"{name}.{'.'.join(suffix)}"
                offset += 1
                break
            offset += 1
            if offset < len(array):
                is_name, ref = self._is_name(array[offset])
            else:
                is_name = False
                ref = None
        return name.strip("."), offset

    def _decode_question(self, cbor_question):
        name, offset = self._decode_name(cbor_question)
        if len(cbor_question[offset:]) == 0:
            rdclass = dns.rdataclass.IN
            rdtype = dns.rdatatype.AAAA
        elif len(cbor_question[offset:]) == 1:
            rdclass = dns.rdataclass.IN
            rdtype = self.deref(cbor_question[offset])
        elif len(cbor_question[offset:]) == 2:
            rdclass = self.deref(cbor_question[offset + 1])
            rdtype = self.deref(cbor_question[offset])
        else:
            raise ValueError(f"Invalid length for question {cbor_question!r}")
        return dns.rrset.RRset(
            name=dns.name.from_text(name),
            rdclass=rdclass,
            rdtype=rdtype,
        )

    def _decode_rr(self, name, section, cbor_rr, res):
        cbor_rr = self.deref(cbor_rr)
        if isinstance(cbor_rr, bytes):
            wire_reader = dns.message._WireReader(cbor_rr, lambda msg: None)
            wire_reader.message = dns.message.Message()
            wire_reader._get_section(section, 1)
            if wire_reader.message.opt:
                res.opt = wire_reader.message.opt
            # TODO: tsig
            else:
                res.sections[section].append(wire_reader.message.sections[section][0])
        elif isinstance(cbor_rr, cbor2.CBORTag) and cbor_rr.tag == 141:
            opt_rr = cbor_rr.value
            opt_rr[0] = self.deref(opt_rr[0])
            if isinstance(opt_rr[0], int):
                udp_payload_size = opt_rr[0]
                offset = 1
            else:
                udp_payload_size = 512
                offset = 0
            options = []
            otype = None
            for i, item in enumerate(opt_rr[offset]):
                if (i % 2) == 0 and isinstance(item, int):
                    otype = item
                elif (i % 2) == 1 and isinstance(item, bytes) and otype is not None:
                    options.append(dns.edns.GenericOption(otype, item))
                    otype = None
                else:
                    raise ValueError(
                        f"Unexpected format of option list {opt_rr[offset]}"
                    )
            opt = dns.rdtypes.ANY.OPT.OPT(udp_payload_size, dns.rdatatype.OPT, options)
            rem = (len(opt_rr) - offset) - 1
            flags = utils.reverse_u16(self.deref(opt_rr[offset + 1])) if rem > 0 else 0
            rcode = self.deref(opt_rr[offset + 2]) if rem > 1 else 0
            version = self.deref(opt_rr[offset + 3]) if rem > 2 else 0
            ttl = (rcode & 0xFF) << 24
            ttl |= (version & 0xFF) << 16
            ttl |= flags & 0xFFFF
            rrset = dns.rrset.RRset(
                dns.name.from_text("."), udp_payload_size, dns.rdatatype.OPT
            )
            rrset.add(opt, ttl)
            res.sections[section].append(rrset)
        elif isinstance(cbor_rr, list):
            if len(cbor_rr) < 2:  # or len(cbor_rr) > 5:
                raise ValueError(f"Resource record of unexpected length {cbor_rr!r}")
            cbor_rr[0] = self.deref(cbor_rr[0])
            if isinstance(cbor_rr[0], int):
                name = name
                ttl = cbor_rr[0]
                offset = 1
            else:
                name_str, name_offset = self._decode_name(cbor_rr)
                name = dns.name.from_text(name_str)
                if (name_offset + 1) > len(cbor_rr):
                    raise ValueError(
                        f"Resource record of unexpected length {cbor_rr!r}"
                        f" {name_offset}"
                    )
                ttl = self.deref(cbor_rr[name_offset])
                offset = name_offset + 1
            cbor_rr[offset] = self.deref(cbor_rr[offset])
            if isinstance(cbor_rr[offset], int):
                rdtype = cbor_rr[offset]
                offset += 1
                cbor_rr[offset] = self.deref(cbor_rr[offset])
                if isinstance(cbor_rr[offset], int):
                    rdclass = cbor_rr[offset]
                    offset += 1
                else:
                    rdclass = dns.rdataclass.IN
            else:
                rdtype = dns.rdatatype.AAAA
                rdclass = dns.rdataclass.IN

            # rdata = self.deref(cbor_rr[offset])
            is_name, _ = self._is_name(cbor_rr[offset])
            if is_name:
                name_str, name_offset = self._decode_name(cbor_rr[offset:])
                offset += name_offset
                if offset < len(cbor_rr):
                    raise ValueError(
                        f"Resource record of unexpected length {cbor_rr!r}"
                    )
                rdata = dns.name.from_text(name_str).to_wire()
            else:
                rdata = self.deref(cbor_rr[offset])
                if isinstance(rdata, int):
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
        elif sections == 2:
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
                orig_query = cbor2.loads(orig_query)
            orig_query = self.decode_query(orig_query)
            # reset ref_idx
            self._ref_idx = []
        if obj is None:
            obj = self.cbor_decoder.decode()
        if not isinstance(obj, list):
            raise ValueError(f"Unexpected response object {obj!r}")
        try:
            if packed:
                if len(obj) != 2:
                    raise ValueError(f"Unexpected packed representation {obj!r}")
                if not isinstance(obj[0], list):
                    raise ValueError(f"Unexpected packing table {obj[0]!r}")
                self.packing_table = obj[0]
                obj = obj[1]
                if not isinstance(obj, list):
                    raise ValueError(f"Unexpected response object {obj!r}")
                self._unpack_packing_table()
            offset, res = self._init_msg_type(obj, dns.message.Message, 0x8000)
            sections = len(obj) - offset
            if sections <= 4:
                question_section = 0
                if (
                    sections > 1
                    and len(obj[offset]) > 0
                    and not isinstance(obj[offset][0], list)
                ):
                    res.question = [self._decode_question(obj[offset])]
                    offset += 1
                    question_section += 1
                else:
                    if orig_query is None:
                        raise ValueError(f"No question provided for {obj!r}")
                    res.question = orig_query.question
                answer = obj[offset]
                additional = []
                authority = []
                if sections == 2 + question_section:
                    authority = obj[offset + 1]
                elif sections == 3 + question_section:
                    additional = obj[offset + 2]
                    authority = obj[offset + 1]
            else:
                raise ValueError(
                    f"Unexpected number of sections {sections} in response object "
                    f"{obj!r}"
                )
            name = res.question[0].name
            for rr in answer:
                self._decode_rr(name, dns.message.ANSWER, rr, res)
            for rr in authority:
                self._decode_rr(name, dns.message.AUTHORITY, rr, res)
            for rr in additional:
                self._decode_rr(name, dns.message.ADDITIONAL, rr, res)
            return res
        finally:
            self.packing_table = None

    @contextlib.contextmanager
    def _prepare_ref_idx(self):
        self._ref_idx = []
        yield
        self._ref_idx = None

    def decode(
        self,
        msg_type: MsgType,
        orig_query: Optional[Union[bytes, list]] = None,
        packed: bool = False,
        obj: list = None,
    ) -> dns.message.Message:
        assert self._ref_idx is None
        with self._prepare_ref_idx():
            if msg_type == MsgType.QUERY:
                return self.decode_query(obj=obj)
            elif msg_type == MsgType.RESPONSE:
                return self.decode_response(
                    orig_query=orig_query, packed=packed, obj=obj
                )
            else:
                raise ValueError(r"Unexpected message type {msg_type!r}")
