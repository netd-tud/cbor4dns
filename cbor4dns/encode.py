"""
Provides the encoder for encoding DNS messages to application/dns+cbor
"""

import contextlib
import enum
import io
import itertools
from typing import List, Mapping, Optional, Tuple, Union

import cbor2
import dns.message
import dns.name
import dns.rdata
import dns.rdtypes.nsbase
import dns.rdtypes.svcbbase
import dns.rrset
from dns.rdataclass import RdataClass
from dns.rdatatype import RdataType

from . import trie
from . import utils
from .utils import RefIdx


class TypeSpec:
    def __init__(
        self,
        record_type: RdataType = RdataType.AAAA,
        record_class: RdataClass = RdataClass.IN,
    ):
        self.record_type = record_type
        self.record_class = record_class

    def __eq__(self, other):
        return (
            self.record_type == other.record_type
            and self.record_class == other.record_class
        )

    def to_obj(self) -> list:
        if self.record_class != RdataClass.IN:
            return [self.record_type, self.record_class]
        if self.record_type != RdataType.AAAA:
            return [self.record_type]
        return []


class HasTypeSpec:
    def __init__(self, type_spec: TypeSpec):
        self.type_spec = type_spec

    @property
    def record_type(self):
        return self.type_spec.record_type

    @property
    def record_class(self):
        return self.type_spec.record_class


class Question(HasTypeSpec):
    def __init__(self, name: dns.name.Name, type_spec: TypeSpec, ref_idx: RefIdx):
        super().__init__(type_spec)
        self.ref_idx = ref_idx
        self.name = name

    def __eq__(self, other):
        return self.name.labels == other.name.labels and self.type_spec == other.type_spec

    def walk(self):
        for obj in self.to_obj():
            yield obj

    def to_obj(self) -> list:
        res = self.ref_idx.add(self.name)
        res.extend(self.type_spec.to_obj())
        return res

    @classmethod
    def from_obj(cls, obj: list, ref_idx: RefIdx):
        offset = 0
        if not isinstance(obj[0], str):
            raise ValueError(
                f"Expected name component in first element of question {obj}"
            )
        name = []
        for comp in obj:
            if isinstance(comp, str):
                offset += 1
                name.append(comp.encode("utf-8"))
            elif isinstance(comp, cbor2.CBORTag) and comp.tag == ref_idx.tag:
                raise ValueError(f"Unexpected name reference in question {obj}")
            else:
                break
        if not name or name[-1] != b"":
            name.append(b"")
        if not obj or (len(obj) - offset) > 2:
            raise ValueError(f"Unexpected question length for question {obj}")
        try:
            record_type = obj[offset]
        except IndexError:
            record_type = RdataType.AAAA
        try:
            record_class = obj[offset + 1]
        except IndexError:
            record_class = RdataClass.IN
        return cls(dns.name.Name(name), TypeSpec(record_type, record_class), ref_idx)


class FlagsBase:
    enforce_flags_default: bool = False
    reverse_flags: bool = False

    def __init__(self, default_flags: int, flags: Optional[int] = None):
        self._flags = default_flags if flags is None else flags
        self._reversed_flags = None
        self.default_flags = default_flags

    @property
    def flags(self):
        if self.reverse_flags:
            if self._reversed_flags is None:
                self._reversed_flags = utils.reverse_u16(self._flags)
            return self._reversed_flags
        return self._flags

    def walk(self):
        for obj in self.to_obj():
            yield obj

    def to_obj(self) -> list:
        if not self.enforce_flags_default and self.flags != self.default_flags:
            return [self.flags]
        return []


class OptRcodeVFlags(FlagsBase):
    reverse_flags = True

    def __init__(self, ttl):
        super().__init__(0x0000, ttl & 0x0000FFFF)
        self.rcode = (ttl & 0xFF000000) >> 24
        self.version = (ttl & 0x00FF0000) >> 16

    def walk(self):
        for obj in self.to_obj():
            yield obj

    def to_obj(self):
        if self.version == 0:
            if self.enforce_flags_default or self.flags == self.default_flags:
                if self.rcode == 0:
                    return []
                return [self.rcode]
            return [self.rcode, self.flags]
        return [self.rcode, self.flags, self.version]


class OptRR:
    opt_tag = 141

    def __init__(
        self,
        udp_payload_size: int,
        options: List[Tuple[int, bytes]],
        rcode_v_flags: OptRcodeVFlags,
    ):
        self.udp_payload_size = udp_payload_size
        self.options = options
        self.rcode_v_flags = rcode_v_flags

    def walk(self):
        for obj in self.to_obj():
            if isinstance(obj, list):
                for item in obj:
                    yield item
            else:
                yield obj

    def to_obj(self):
        res = []
        if self.udp_payload_size > 512:
            res.append(self.udp_payload_size)
        res.append(dict(self.options))
        res.extend(self.rcode_v_flags.to_obj())
        return cbor2.CBORTag(self.opt_tag, res)


class RR(HasTypeSpec):
    def __init__(
        self,
        name: dns.name.Name,
        type_spec: TypeSpec,
        ttl: int,
        rdata: dns.rdata.Rdata,
        question: Question,
        ref_idx: RefIdx,
    ):
        if ttl < 0:
            raise ValueError(f"ttl={ttl} must not be < 0")
        assert rdata is not None or (
            type_spec.record_type in [
                RdataType.SOA,
                RdataType.MX,
                RdataType.SRV,
                RdataType.SVCB,
                RdataType.HTTPS,
            ]
        ), "rdata missing for non-structured rdata type"
        super().__init__(type_spec)
        self.question = question
        self.ref_idx = ref_idx
        self.name = name
        self.ttl = ttl
        self.rdata = rdata

    def walk(self):
        for obj in self.to_obj():
            yield obj

    def to_obj(self) -> list:
        res = []
        if self.question.name.labels != self.name.labels:
            res.extend(self.ref_idx.add(self.name))
        res.append(self.ttl)
        res.extend(self.type_spec.to_obj())
        if self.rdata is not None:
            if isinstance(self.rdata, dns.rdtypes.nsbase.NSBase):
                res.extend(self.ref_idx.add(self.rdata.target))
            else:
                res.append(self.rdata.to_wire())
        return res

    @staticmethod
    def _parse_options(options):
        res = []
        for opt in options:
            with io.BytesIO() as fp:
                opt.to_wire(fp)
                byts = fp.getvalue()
                res.append((opt.otype, byts))
        return res

    @classmethod
    def rrs_from_rrset(cls, rrset, question: Question, ref_idx: RefIdx) -> list:
        if isinstance(rrset, dns.rrset.RRset):
            if rrset.rdtype == RdataType.OPT:
                return [
                    OptRR(
                        rr.payload,
                        cls._parse_options(rr.options),
                        OptRcodeVFlags(rrset.ttl),
                    )
                    for rr in rrset
                ]
            elif rrset.rdtype == RdataType.TSIG:
                with io.BytesIO() as fp:
                    rrset.to_wire(fp)
                    byts = fp.getvalue()
                    return [byts]
            elif rrset.rdtype == RdataType.SOA:
                return [
                    SOARR(
                        rrset.name,
                        TypeSpec(rrset.rdtype, rrset.rdclass),
                        rrset.ttl,
                        rr.mname,
                        rr.rname,
                        rr.serial,
                        rr.refresh,
                        rr.retry,
                        rr.expire,
                        rr.minimum,
                        question,
                        ref_idx,
                    )
                    for rr in rrset
                ]
            elif rrset.rdtype == RdataType.MX:
                return [
                    MXRR(
                        rrset.name,
                        TypeSpec(rrset.rdtype, rrset.rdclass),
                        rrset.ttl,
                        rr.preference,
                        rr.exchange,
                        question,
                        ref_idx,
                    )
                    for rr in rrset
                ]
            elif rrset.rdtype == RdataType.SRV:
                return [
                    SRVRR(
                        rrset.name,
                        TypeSpec(rrset.rdtype, rrset.rdclass),
                        rrset.ttl,
                        rr.priority,
                        rr.port,
                        rr.target,
                        question,
                        ref_idx,
                        weight=rr.weight,
                    )
                    for rr in rrset
                ]
            elif rrset.rdtype in [RdataType.SVCB, RdataType.HTTPS]:
                return [
                    SVCBRR(
                        rrset.name,
                        TypeSpec(rrset.rdtype, rrset.rdclass),
                        rrset.ttl,
                        rr.params,
                        question,
                        ref_idx,
                        svc_priority=rr.priority,
                        target=rr.target,
                    )
                    for rr in rrset
                ]
            return [
                cls(
                    rrset.name,
                    TypeSpec(rrset.rdtype, rrset.rdclass),
                    rrset.ttl,
                    rr,
                    question,
                    ref_idx,
                )
                for rr in rrset
            ]
        else:
            res = [rrset.to_wire()]
            return res

    @classmethod
    def rrs_from_section(
        cls, section: List, question: Question, ref_idx: RefIdx
    ) -> list:
        res = list(
            itertools.chain.from_iterable(
                cls.rrs_from_rrset(rrset, question, ref_idx) for rrset in section
            ),
        )
        return res


class StructuredRR(RR):
    def walk(self):
        for obj in super().walk():
            if isinstance(obj, list):
                for elem in obj:
                    yield elem
            else:
                yield obj


class SOARR(StructuredRR):
    def __init__(
        self,
        name: dns.name.Name,
        type_spec: TypeSpec,
        ttl: int,
        mname: dns.name.Name,
        rname: dns.name.Name,
        serial: int,
        refresh: int,
        retry: int,
        expire: int,
        minimum: int,
        question: Question,
        ref_idx: RefIdx,
    ):
        assert 0 <= serial <= 0xffffffff
        assert 0 <= refresh <= 0xffffffff
        assert 0 <= retry <= 0xffffffff
        assert 0 <= expire <= 0xffffffff
        assert 0 <= minimum <= 0xffffffff
        super().__init__(name, type_spec, ttl, None, question, ref_idx)
        self.mname = mname
        self.rname = rname
        self.serial = serial
        self.refresh = refresh
        self.retry = retry
        self.expire = expire
        self.minimum = minimum

    def to_obj(self):
        res = super().to_obj()
        rr = []
        rr.extend(self.ref_idx.add(self.mname))
        rr.append(self.serial)
        rr.append(self.refresh)
        rr.append(self.retry)
        rr.append(self.expire)
        rr.append(self.minimum)
        rr.extend(self.ref_idx.add(self.rname))
        res.append(rr)
        return res


class MXRR(StructuredRR):
    def __init__(
        self,
        name: dns.name.Name,
        type_spec: TypeSpec,
        ttl: int,
        preference: int,
        exchange: dns.name.Name,
        question: Question,
        ref_idx: RefIdx,
    ):
        assert 0 <= preference <= 0xffff
        super().__init__(name, type_spec, ttl, None, question, ref_idx)
        self.preference = preference
        self.exchange = exchange

    def to_obj(self):
        res = super().to_obj()
        rr = []
        rr.append(self.preference)
        rr.extend(self.ref_idx.add(self.exchange))
        res.append(rr)
        return res


class SRVRR(StructuredRR):
    def __init__(
        self,
        name: dns.name.Name,
        type_spec: TypeSpec,
        ttl: int,
        priority: int,
        port: int,
        target: dns.name.Name,
        question: Question,
        ref_idx: RefIdx,
        weight: int = 0,
    ):
        assert 0 <= priority <= 0xffff
        assert 0 <= port <= 0xffff
        assert 0 <= weight <= 0xffff
        super().__init__(name, type_spec, ttl, None, question, ref_idx)
        self.priority = priority
        self.weight = weight
        self.port = port
        self.target = target

    def to_obj(self):
        res = super().to_obj()
        rr = []
        rr.append(self.priority)
        if self.weight != 0:
            rr.append(self.weight)
        rr.append(self.port)
        rr.extend(self.ref_idx.add(self.target))
        res.append(rr)
        return res


class SVCBRR(StructuredRR):
    def __init__(
        self,
        name: dns.name.Name,
        type_spec: TypeSpec,
        ttl: int,
        svc_params: Mapping[dns.rdtypes.svcbbase.ParamKey, dns.rdtypes.svcbbase.Param],
        question: Question,
        ref_idx: RefIdx,
        svc_priority: int = 0,
        target: Optional[dns.name.Name] = None,
    ):
        assert 0 <= svc_priority <= 0xffff
        super().__init__(name, type_spec, ttl, None, question, ref_idx)
        self.svc_priority = svc_priority
        if target is None:
            self.target = dns.name.Name([b""])
        else:
            self.target = target
        self.svc_params = svc_params

    def walk(self):
        for obj in super().walk():
            if isinstance(obj, list):
                for key, value in obj:
                    yield int(key)
                    with io.BytesIO() as f:
                        value.to_wire(f)
                        val = f.getvalue()
                    yield val
            else:
                yield obj

    def to_obj(self):
        res = super().to_obj()
        rr = []
        if self.svc_priority != 0:
            rr.append(self.svc_priority)
        if self.target.labels != (b"",):
            rr.extend(self.ref_idx.add(self.target))
        svc_params = []
        for key, value in self.svc_params.items():
            with io.BytesIO() as f:
                value.to_wire(f)
                val = f.getvalue()
            svc_params.append((int(key), val))
        rr.append(svc_params)
        res.append(rr)
        return res


class QueryFlags(FlagsBase):
    def __init__(
        self,
        flags: int = 0,
    ):
        super().__init__(0x0000, flags)


class ExtraSections:
    def __init__(
        self,
        authority: Optional[List[Union[RR, bytes]]] = None,
        additional: Optional[List[Union[RR, bytes]]] = None,
    ):
        self.authority = authority
        self.additional = additional

    def __bool__(self):
        return (
            self.authority is not None
            and len(self.authority) > 0
            and self.additional is not None
            and len(self.additional) > 0
        )

    def walk(self):
        if self.authority:
            for memb in self.authority:
                if isinstance(memb, RR):
                    for obj in memb.walk():
                        yield obj
                else:
                    yield memb
        if self.additional:
            for memb in self.additional:
                if isinstance(memb, RR):
                    for obj in memb.walk():
                        yield obj
                else:
                    yield memb

    def to_obj(self) -> list:
        if self.authority:
            if self.additional:
                return [self.authority, self.additional]
            else:
                return [self.authority, []]
        if self.additional:
            return [self.additional]
        return []


class QueryExtraSections(ExtraSections):
    def __init__(
        self,
        answers: Optional[List[Union[RR, bytes]]] = None,
        authority: Optional[List[Union[RR, bytes]]] = None,
        additional: Optional[List[Union[RR, bytes]]] = None,
    ):
        self.answers = answers
        super().__init__(authority, additional)

    def __bool__(self):
        return (self.answers is not None and len(self.answers) > 0) and bool(super())

    def walk(self):
        if self.answers:
            for memb in self.answers:
                if isinstance(memb, RR):
                    for obj in memb.walk():
                        yield obj
                else:
                    yield obj
        for obj in super().walk():
            yield obj

    def to_obj(self) -> list:
        if self.answers:
            if self.authority:
                if self.additional:
                    return [self.answers, self.authority, self.additional]
                return [self.answers, self.authority, []]
            return [self.answers, [], []]
        return super().to_obj()


class DNSQuery:
    def __init__(
        self,
        flags: QueryFlags,
        question: Question,
        extra: QueryExtraSections,
        ref_idx: RefIdx,
    ):
        self.flags = flags
        self.question = question
        self.extra = extra
        self.ref_idx = ref_idx

    def walk(self):
        for obj in self.flags.walk():
            yield obj
        for obj in self.question.walk():
            yield obj
        for obj in self.extra.walk():
            yield obj

    def to_obj(self) -> list:
        self.ref_idx.clear()
        res = self.flags.to_obj()
        res.append(self.question)
        res.extend(self.extra.to_obj())
        return res


class ResponseFlags(FlagsBase):
    def __init__(
        self,
        flags: int = 0,
    ):
        super().__init__(0x8000, flags)


def _cbor_length_field_length(length):
    if length < 24:
        return 1
    elif length < 256:
        return 2
    elif length < 65536:
        return 3
    elif length < 4294967296:
        return 5
    else:
        return 9


def cbor_int_length(value):
    # Big integers (2 ** 64 and over)
    if value >= 18446744073709551616 or value < -18446744073709551616:
        if value < 0:
            value = -(value + 1)

        bytes_len = (value.bit_length() + 7) // 8
        return 1 + _cbor_length_field_length(bytes_len) + bytes_len
    elif value >= 0:
        return _cbor_length_field_length(value)
    else:
        return _cbor_length_field_length(-(value + 1))


def ref_size(value):
    if value < 16:
        return 1
    elif value < 64:
        return 2
    elif value < 528:
        return 3
    else:
        return 4


class OccurranceCounter:
    VALUE_REF = lambda a, b: a == b  # noqa: E731
    STRAIGHT_REF = lambda a, b: a.startswith(b)  # noqa: E731
    INVERTED_REF = lambda a, b: a.endswith(b)  # noqa: E731

    def __init__(self):
        self.bytes_counter = trie.CountingBytesTrie()
        self.str_int_counter = dict()

    def add(self, value):
        if isinstance(value, bytes):
            self.bytes_counter.insert(value)
        elif isinstance(value, str) or isinstance(value, int):
            if value not in self.str_int_counter:
                self.str_int_counter[value] = 1
            else:
                self.str_int_counter[value] += 1

    def __iter__(self):
        for occurrences, value in self.bytes_counter:
            yield occurrences, value, len(value) + _cbor_length_field_length(
                len(value)
            ), OccurranceCounter.STRAIGHT_REF
        for value, occurrences in self.str_int_counter.items():
            yield (
                occurrences,
                value,
                (
                    cbor_int_length(value)
                    if isinstance(value, int)
                    else len(value) + _cbor_length_field_length(len(value))
                ),
                OccurranceCounter.VALUE_REF,
            )


class DNSResponse:
    def __init__(
        self,
        flags: ResponseFlags,
        question: Optional[Question],
        answer: List[Union[RR, bytes]],
        extra: ExtraSections,
        ref_idx: RefIdx,
    ):
        self.flags = flags
        self.question = question
        self.answer = answer
        self.extra = extra
        self.ref_idx = ref_idx

    def walk(self):
        for obj in self.flags.walk():
            yield obj
        if self.question:
            for obj in self.question.walk():
                yield obj
        for memb in self.answer:
            if isinstance(memb, RR):
                for obj in memb.walk():
                    yield obj
            else:
                yield obj
        for obj in self.extra.walk():
            yield obj

    def count(self) -> OccurranceCounter:
        counter = OccurranceCounter()
        for obj in self.walk():
            counter.add(obj)
        return counter

    def to_obj(self) -> list:
        self.ref_idx.clear()
        res = self.flags.to_obj()
        if self.question:
            res.append(self.question)
        res.append(self.answer)
        res.extend(self.extra.to_obj())
        return res


class PackingTable:
    def __init__(self, lst):
        self.lst = lst

    def __iter__(self):
        return iter(self.lst)

    def __getitem__(self, idx):
        return self.lst[idx]


class DefaultPackingTableConstructor:
    def __init__(self, encoder):
        self.encoder = encoder

    def get_packing_table(self, obj):
        counted = [(0, 1, None, None)]
        for occurrences, value, value_len, op in obj.count():
            if occurrences <= 1:
                # exclude from packing table if value only occurs once
                continue
            last_occurrences = counted[-1][1]
            last_value = counted[-1][3]
            savings = (occurrences - 1) * (value_len - 1)
            if savings <= 0:
                # exclude if there are negative savings
                continue
            # append if it is a new value, update if it only is a super-set of the
            # previous value
            if (
                type(last_value) is type(value)
                and last_occurrences == occurrences
                and op(value, last_value)
            ):
                counted[-1] = (savings, occurrences, value_len, value, op)
            else:
                counted.append((savings, occurrences, value_len, value, op))
        res = []
        # Filter out values which length is shorter than the resulting
        # value reference length
        for _, _, value_len, value, op in sorted(
            counted[1:], reverse=True, key=lambda v: (v[1], v[0])
        ):
            if op is OccurranceCounter.VALUE_REF and ref_size(len(res)) >= value_len:
                # TODO: also check if prefix/suffix is shorter
                continue
            res.append(value)
        # Room for optimization: check if affixes in res really bring the desired
        # savings, e.g. in our tests, having
        # - 0.org.afilias-nst.info
        # - c0.org.afilias-nst.info
        # - a0.org.afilias-nst.info
        # in res and compressing the latter two is less effective than not having the
        # 0.org.afilias-nst.info
        return PackingTable(res)


class Encoder:
    packing_table_constructor_type = DefaultPackingTableConstructor

    def __init__(self, fp, packed=False, always_omit_question=False):
        self.fp = fp
        self.packed = packed
        self.ref_idx = None
        self.always_omit_question = always_omit_question
        self.cbor_encoder = self.cbor_encoder_factory(
            packed, fp=fp, default=self.default_encoder
        )
        if self.packed:
            self.counters = {
                str: trie.CountingStringTrie(),
                bytes: trie.CountingBytesTrie(),
                None: dict(),
            }
            self.packing_table = None
        else:
            self.counters = None
            self.packing_table = None

    def cbor_encoder_factory(self, packed, *args, **kwargs):
        outer = self

        class PackedCBOREncoder(cbor2.CBOREncoder):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                # update _encoders to overriding methods
                self._encoders[int] = type(self).encode_int
                self._encoders[bytes] = type(self).encode_bytestring
                self._encoders[str] = type(self).encode_string
                # set to anything but 0 or 1 so that CBOREncoder uses custom encoders
                # above
                self.enc_style = 0xD0
                self.encoding_packing_table = False
                self._reffing_bytes = False
                self._reffing_str = False

            def encode(self, obj):
                if isinstance(obj, DNSResponse) and outer.packing_table:
                    return super().encode([outer.packing_table, obj])
                return super().encode(obj)

            def ref_shared_item(self, value, idx):
                if idx < 16:
                    self.encode_simple_value((idx,))
                else:
                    n = (15 - idx) // 2 if idx % 2 else (idx - 16) // 2
                    self.encode_semantic(cbor2.CBORTag(6, n))

            def ref_straight_rump(self, value, idx):
                if idx == 0:
                    self.encode_semantic(cbor2.CBORTag(6, value))
                elif idx < 32:
                    self.encode_semantic(cbor2.CBORTag(224 + idx, value))
                elif idx < 4096:
                    self.encode_semantic(cbor2.CBORTag(28704 + (idx - 32), value))
                elif idx < (1 << 28):
                    self.encode_semantic(
                        cbor2.CBORTag(1879052288 + (idx - 4096), value)
                    )
                else:  # pragma: no-cover
                    raise RuntimeError("Should not be reached")

            def ref_inverted_rump(self, value, idx):
                if idx < 8:
                    self.encode_semantic(cbor2.CBORTag(216 + idx, value))
                elif idx < 1024:
                    self.encode_semantic(cbor2.CBORTag(27647 + (idx - 8), value))
                elif idx < (1 << 26):
                    self.encode_semantic(
                        cbor2.CBORTag(1811940352 + (idx - 1024), value)
                    )
                else:  # pragma: no-cover
                    raise RuntimeError("Should not be reached")

            def encode_int(self, value):
                if outer.packing_table:
                    for idx, val in enumerate(outer.packing_table):
                        if (
                            not self.encoding_packing_table
                            and isinstance(val, int)
                            and val == value
                            # TODO: check if ref_shared_item yields shorter CBOR code
                        ):
                            self.ref_shared_item(value, idx)
                            return
                super().encode_int(value)

            @contextlib.contextmanager
            def enter_reffing_bytes(self):
                self._reffing_bytes = True
                yield
                self._reffing_bytes = False

            @contextlib.contextmanager
            def enter_reffing_str(self):
                self._reffing_str = True
                yield
                self._reffing_str = False

            def encode_bytestring(self, value):
                if not self._reffing_bytes and outer.packing_table:
                    with self.enter_reffing_bytes():
                        max_match = -1, 0
                        for idx, prefix in enumerate(outer.packing_table):
                            if isinstance(prefix, bytes) and value is not prefix:
                                if value == prefix:
                                    self.ref_shared_item(value, idx)
                                    return
                                elif (
                                    value.startswith(prefix)
                                    and len(prefix) > max_match[1]
                                ):
                                    max_match = idx, len(prefix)
                        if max_match != (-1, 0):
                            value = value[max_match[1] :]
                            self.ref_straight_rump(value, max_match[0])
                            return
                super().encode_bytestring(value)

            def encode_string(self, value):
                if not self._reffing_str and outer.packing_table:
                    with self.enter_reffing_str():
                        max_match = -1, 0
                        for idx, suffix in enumerate(outer.packing_table):
                            if isinstance(suffix, str) and value is not suffix:
                                if value == suffix:
                                    self.ref_shared_item(value, idx)
                                    return
                                elif (
                                    value.endswith(suffix)
                                    and len(suffix) > max_match[1]
                                ):
                                    max_match = idx, len(suffix)
                        if max_match != (-1, 0):
                            # TODO: check if ref_inverted_rump yields shorter CBOR code
                            value = value[: -max_match[1]]
                            self.ref_inverted_rump(value, max_match[0])
                            return
                super().encode_string(value)

        if packed:
            return PackedCBOREncoder(*args, **kwargs)
        return cbor2.CBOREncoder(*args, **kwargs)

    @staticmethod
    def default_encoder(cbor_encoder, value):
        if isinstance(value, (DNSQuery, DNSResponse, Question, RR, OptRR)):
            cbor_encoder.encode(value.to_obj())
        elif isinstance(value, PackingTable):
            try:
                cbor_encoder.encoding_packing_table = True
                cbor_encoder.encode(value.lst)
            finally:
                cbor_encoder.encoding_packing_table = False
        else:
            raise ValueError(f"Can not encode {value} (type {type(value)})")

    def _get_question(self, msg):
        if len(msg.question) > 1:
            raise ValueError(
                f"Can not encode message {msg} with question section longer than 1"
            )
        question_section = msg.question[0]
        return Question(
            question_section.name,
            TypeSpec(question_section.rdtype, question_section.rdclass),
            self.ref_idx,
        )

    def _get_additional(self, msg, question):
        additional = RR.rrs_from_section(msg.additional, question, self.ref_idx)
        if msg.opt:
            additional += RR.rrs_from_section([msg.opt], question, self.ref_idx)
        if msg.tsig:
            additional += RR.rrs_from_section(msg.tsig, question, self.ref_idx)
        return additional

    def _encode_query(self, msg: dns.message.Message):
        question = self._get_question(msg)
        return DNSQuery(
            QueryFlags(msg.flags),
            question,
            QueryExtraSections(
                answers=RR.rrs_from_section(msg.answer, question, self.ref_idx),
                authority=RR.rrs_from_section(msg.authority, question, self.ref_idx),
                additional=self._get_additional(msg, question),
            ),
            self.ref_idx,
        )

    def _encode_response(
        self, msg: dns.message.Message, orig_question: Optional[Question]
    ):
        question = self._get_question(msg)
        extra_sections = ExtraSections(
            authority=RR.rrs_from_section(
                msg.authority, orig_question or question, self.ref_idx
            ),
            additional=self._get_additional(msg, orig_question or question),
        )
        if self.always_omit_question or (orig_question and question == orig_question):
            question = None
        return DNSResponse(
            ResponseFlags(msg.flags),
            question,
            RR.rrs_from_section(msg.answer, orig_question or question, self.ref_idx),
            extra_sections,
            self.ref_idx,
        )

    def encode(
        self,
        msg: Union[bytes, dns.message.Message],
        orig_query: Optional[Union[bytes, list]] = None,
    ):
        if not isinstance(msg, dns.message.Message):
            msg = dns.message.from_wire(msg, one_rr_per_rrset=True)
        self.ref_idx = RefIdx()
        if msg.flags & msg.flags.QR:  # msg is response
            if orig_query:
                if isinstance(orig_query, bytes):
                    orig_query = cbor2.loads(orig_query)
                query_ref_idx = RefIdx()
                orig_question = Question.from_obj(
                    [q for q in orig_query if isinstance(q, list)][0],
                    query_ref_idx,
                )
                del query_ref_idx
            else:
                orig_question = None
            res = self._encode_response(msg, orig_question)
            if self.packed:
                packing_table_constr = self.packing_table_constructor_type(self)
                self.packing_table = packing_table_constr.get_packing_table(res)
        else:
            res = self._encode_query(msg)
        self.cbor_encoder.encode(res)
        self.ref_idx = None
