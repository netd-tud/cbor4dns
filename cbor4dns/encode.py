"""
Provides the encoder for encoding DNS messages to application/dns+cbor
"""

import contextlib
import io
import itertools
from typing import List, Optional, Tuple, Union

import cbor2
import dns.message
import dns.name
import dns.rdtypes.nsbase
import dns.rrset
from dns.rdataclass import RdataClass
from dns.rdatatype import RdataType

from . import trie
from . import utils


def _escapify(label: Union[bytes, str]) -> str:
    if isinstance(label, bytes):
        return label.decode("utf-8")
    else:
        return dns.name._escapify(label)


class UnescapedIDNA2008Codec(dns.name.IDNA2008Codec):
    def decode(self, label: bytes) -> str:
        if not self.strict_decode:
            if self.is_idna(label):
                try:
                    slabel = label[4:].decode("punycode")
                    if len(label) < len(slabel.encode("utf-8")):
                        return label.decode("ascii")
                    return _escapify(slabel)
                except Exception as e:
                    raise dns.name.IDNAException(idna_exception=e)
            else:
                return _escapify(label)
        if label == b"":
            return ""
        if not dns.name.have_idna_2008:
            raise dns.name.NoIDNA2008
        try:
            ulabel = dns.name.idna.ulabel(label)
            if self.uts_46:
                ulabel = dns.name.idna.uts46_remap(ulabel, False, self.transitional)
            if len(label) < len(ulabel.encode("utf-8")):
                return label.decode("ascii")
            return _escapify(ulabel)
        except (dns.name.idna.IDNAError, UnicodeError) as e:
            raise dns.name.IDNAException(idna_exception=e)


IDNA_CODEC = UnescapedIDNA2008Codec(True, False, True, False)


def name_to_text(name):
    text = name.to_unicode(omit_final_dot=True, idna_codec=IDNA_CODEC)
    return text


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
    def __init__(self, name: str, type_spec: TypeSpec):
        super().__init__(type_spec)
        self.name = name

    def __eq__(self, other):
        return self.name == other.name and self.type_spec == other.type_spec

    def walk(self):
        for obj in self.to_obj():
            yield obj

    def to_obj(self) -> list:
        res = [self.name]
        res.extend(self.type_spec.to_obj())
        return res

    @classmethod
    def from_obj(cls, obj: list):
        if not obj or len(obj) > 3:
            raise ValueError(f"Unexpected question length for question {obj}")
        name = dns.name.from_text(obj[0])
        try:
            record_type = obj[1]
        except IndexError:
            record_type = RdataType.AAAA
        try:
            record_class = obj[2]
        except IndexError:
            record_class = RdataClass.IN
        return cls(name, TypeSpec(record_type, record_class))


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
        res.append(list(itertools.chain.from_iterable(self.options)))
        res.extend(self.rcode_v_flags.to_obj())
        return cbor2.CBORTag(self.opt_tag, res)


class RR(HasTypeSpec):
    encode_opts = True

    def __init__(
        self,
        name: str,
        type_spec: TypeSpec,
        ttl: int,
        rdata: Union[int, bytes, str],
        question: Question,
    ):
        if ttl < 0:
            raise ValueError(f"ttl={ttl} must not be < 0")
        super().__init__(type_spec)
        self.question = question
        self.name = name
        self.ttl = ttl
        self.rdata = rdata

    def walk(self):
        for obj in self.to_obj():
            yield obj

    def to_obj(self) -> list:
        res = []
        if self.question.name != self.name:
            res.append(name_to_text(self.name))
        res.append(self.ttl)
        res.extend(self.type_spec.to_obj())
        if isinstance(self.rdata, dns.rdtypes.nsbase.NSBase):
            res.append(name_to_text(self.rdata.target))
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
    def rrs_from_rrset(cls, rrset, question: Question) -> list:
        if isinstance(rrset, dns.rrset.RRset):
            if cls.encode_opts and rrset.rdtype == RdataType.OPT:
                return [
                    OptRR(
                        rr.payload,
                        cls._parse_options(rr.options),
                        OptRcodeVFlags(rrset.ttl),
                    )
                    for rr in rrset
                ]
            elif rrset.rdtype == RdataType.TSIG or (
                not cls.encode_opts and rrset.rdtype == RdataType.OPT
            ):
                with io.BytesIO() as fp:
                    rrset.to_wire(fp)
                    byts = fp.getvalue()
                    return [byts]
            return [
                cls(
                    rrset.name,
                    TypeSpec(rrset.rdtype, rrset.rdclass),
                    rrset.ttl,
                    rr,
                    question,
                )
                for rr in rrset
            ]
        else:
            res = [rrset.to_wire()]
            return res

    @classmethod
    def rrs_from_section(cls, section: List, question: Question) -> list:
        res = list(
            itertools.chain.from_iterable(
                cls.rrs_from_rrset(rrset, question) for rrset in section
            ),
        )
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


class DNSQuery:
    def __init__(
        self,
        flags: QueryFlags,
        question: Question,
        extra: ExtraSections,
    ):
        self.flags = flags
        self.question = question
        self.extra = extra

    def walk(self):
        for obj in self.flags.walk():
            yield obj
        for obj in self.question.walk():
            yield obj
        for obj in self.extra.walk():
            yield obj

    def to_obj(self) -> list:
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
        self.str_counter = trie.CountingStringTrie()
        self.int_counter = dict()

    def add(self, value):
        if isinstance(value, bytes):
            self.bytes_counter.insert(value)
        elif isinstance(value, str):
            self.str_counter.insert(value[::-1])
        elif isinstance(value, int):
            if value not in self.int_counter:
                self.int_counter[value] = 1
            else:
                self.int_counter[value] += 1

    def __iter__(self):
        for occurrences, value in self.bytes_counter:
            yield occurrences, value, len(value) + _cbor_length_field_length(
                len(value)
            ), OccurranceCounter.STRAIGHT_REF
        for occurrences, value in self.str_counter:
            yield occurrences, value[::-1], len(value) + _cbor_length_field_length(
                len(value)
            ), OccurranceCounter.INVERTED_REF
        for value, occurrences in self.int_counter.items():
            yield (
                occurrences,
                value,
                cbor_int_length(value),
                OccurranceCounter.VALUE_REF,
            )


class DNSResponse:
    def __init__(
        self,
        flags: ResponseFlags,
        question: Optional[Question],
        answer: List[Union[RR, bytes]],
        extra: ExtraSections,
    ):
        self.flags = flags
        self.question = question
        self.answer = answer
        self.extra = extra

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
                # set to anything but 0 or 1 to use custom encoding
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
        elif isinstance(value, dns.name.Name):
            cbor_encoder.encode(name_to_text(value))
        elif isinstance(value, PackingTable):
            try:
                cbor_encoder.encoding_packing_table = True
                cbor_encoder.encode(value.lst)
            finally:
                cbor_encoder.encoding_packing_table = False
        else:
            raise ValueError(f"Can not encode {value} (type {type(value)})")

    @staticmethod
    def _get_question(msg):
        if len(msg.question) > 1:
            raise ValueError(
                f"Can not encode message {msg} with question section longer than 1"
            )
        question_section = msg.question[0]
        return Question(
            question_section.name,
            TypeSpec(question_section.rdtype, question_section.rdclass),
        )

    def _get_additional(self, msg, question):
        additional = RR.rrs_from_section(msg.additional, question)
        if msg.opt:
            additional += RR.rrs_from_section([msg.opt], question)
        if msg.tsig:
            additional += RR.rrs_from_section(msg.tsig, question)
        return additional

    def _encode_query(self, msg: dns.message.Message):
        question = self._get_question(msg)
        return DNSQuery(
            QueryFlags(msg.flags),
            question,
            ExtraSections(
                authority=RR.rrs_from_section(msg.authority, question),
                additional=self._get_additional(msg, question),
            ),
        )

    def _encode_response(
        self, msg: dns.message.Message, orig_question: Optional[Question]
    ):
        question = self._get_question(msg)
        extra_sections = ExtraSections(
            authority=RR.rrs_from_section(msg.authority, orig_question or question),
            additional=self._get_additional(msg, orig_question or question),
        )
        if self.always_omit_question or (orig_question and question == orig_question):
            question = None
        return DNSResponse(
            ResponseFlags(msg.flags),
            question,
            RR.rrs_from_section(msg.answer, orig_question or question),
            extra_sections,
        )

    def encode(
        self,
        msg: Union[bytes, dns.message.Message],
        orig_query: Optional[Union[bytes, list]] = None,
    ):
        if not isinstance(msg, dns.message.Message):
            msg = dns.message.from_wire(msg, one_rr_per_rrset=True)
        if msg.flags & msg.flags.QR:  # msg is response
            if orig_query:
                if isinstance(orig_query, bytes):
                    orig_query = cbor2.loads(orig_query)
                orig_question = Question.from_obj(
                    [q for q in orig_query if isinstance(q, list)][0]
                )
            else:
                orig_question = None
            res = self._encode_response(msg, orig_question)
            if self.packed:
                packing_table_constr = self.packing_table_constructor_type(self)
                self.packing_table = packing_table_constr.get_packing_table(res)
        else:
            res = self._encode_query(msg)
        self.cbor_encoder.encode(res)
