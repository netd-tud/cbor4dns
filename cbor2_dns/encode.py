"""
Provides the encoder for encoding DNS messages to application/dns+cbor
"""

import io
import itertools
from typing import List, Optional, Union

import cbor2
import dns.message
import dns.name
import dns.rrset
from dns.rdataclass import RdataClass
from dns.rdatatype import RdataType

from . import trie


TEXT_STRING_TYPES = [
    RdataType.NS,
    RdataType.CNAME,
    RdataType.PTR,
    # TODO fill further
]


class TypeSpec:
    def __init__(
        self,
        record_type: RdataType = RdataType.AAAA,
        record_class: RdataClass = RdataClass.IN
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


class RR(HasTypeSpec):
    def __init__(
        self,
        name: str,
        type_spec: TypeSpec,
        ttl: int,
        rdata: Union[int, bytes, str],
        question: Question,
        tries=None,
    ):
        if ttl < 0:
            raise ValueError(f"ttl={ttl} must not be < 0")
        super().__init__(type_spec)
        self.question = question
        self.name = name
        self.ttl = ttl
        self.rdata = rdata
        self.tries = tries

    def walk(self):
        for obj in self.to_obj():
            yield obj

    def to_obj(self) -> list:
        res = []
        if self.question.name != self.name:
            if self.tries:
                self.tries[str].insert(self.name.to_text(omit_final_dot=True)[::-1])
            res.append(self.name)
        res.append(self.ttl)
        res.extend(self.type_spec.to_obj())
        if self.rdata.rdtype in TEXT_STRING_TYPES:
            res.append(self.rdata.to_text(omit_final_dot=True).strip("."))
            if self.tries:
                self.tries[str].insert(res[-1][::-1])
        else:
            res.append(self.rdata.to_wire())
            if self.tries:
                self.tries[bytes].insert(res[-1])
        return res

    @staticmethod
    def rrs_from_rrset(rrset, question: Question, tries=None) -> list:
        if isinstance(rrset, dns.rrset.RRset):
            if rrset.rdtype in [RdataType.OPT, RdataType.TSIG]:
                with io.BytesIO() as fp:
                    rrset.to_wire(fp)
                    byts = fp.getvalue()
                    if tries:
                        tries[bytes].insert(byts)
                    return [byts]
            return [
                RR(
                    rrset.name,
                    TypeSpec(rrset.rdtype, rrset.rdclass),
                    rrset.ttl,
                    rr,
                    question,
                    tries,
                )
                for rr in rrset
            ]
        else:
            res = [rrset.to_wire()]
            if tries:
                tries[bytes].insert(res[0])
            return res

    @staticmethod
    def rrs_from_section(section: List, question: Question, tries=None) -> list:
        return list(
            itertools.chain.from_iterable(
                RR.rrs_from_rrset(rrset, question, tries=tries)
                for rrset in section
            ),
        )


class IDFlagsBase:
    enforce_id_default: bool = False
    enforce_flags_default: bool = False

    def __init__(self, default_flags: int, id: int = 0, flags: Optional[int] = None):
        self.flags = default_flags if flags is None else flags
        self.default_flags = default_flags
        self.id = id

    def walk(self):
        for obj in self.to_obj():
            yield obj

    def to_obj(self) -> list:
        if not self.enforce_flags_default and self.flags != self.default_flags:
            return [self.id, self.flags]
        if not self.enforce_id_default and self.id != 0:
            return [self.id]
        return []


class QueryIDFlags(IDFlagsBase):
    def __init__(
        self,
        id: int = 0,
        flags: int = 0,
    ):
        super().__init__(0x0000, id, flags)


class ExtraSections:
    def __init__(
        self,
        authority: Optional[List[Union[RR, bytes]]] = None,
        additional: Optional[List[Union[RR, bytes]]] = None,
    ):
        self.authority = authority
        self.additional = additional

    def walk(self):
        if self.authority:
            for memb in self.authority:
                if isinstance(memb, RR):
                    for obj in memb.walk():
                        yield obj
                else:
                    yield obj
        if self.additional:
            for memb in self.additional:
                if isinstance(memb, RR):
                    for obj in memb.walk():
                        yield obj
                else:
                    yield obj

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
        id_flags: QueryIDFlags,
        question: Question,
        extra: ExtraSections,
    ):
        self.id_flags = id_flags
        self.question = question
        self.extra = extra

    def walk(self):
        for obj in self.id_flags.walk():
            yield obj
        for obj in self.question.walk():
            yield obj
        for obj in self.extra.walk():
            yield obj

    def to_obj(self) -> list:
        res = self.id_flags.to_obj()
        res.append(self.question)
        res.extend(self.extra.to_obj())
        return res


class ResponseIDFlags(IDFlagsBase):
    def __init__(
        self,
        id: int = 0,
        flags: int = 0,
    ):
        super().__init__(0x8000, id, flags)


class DNSResponse:
    def __init__(
        self,
        id_flags: ResponseIDFlags,
        question: Optional[Question],
        answer: List[Union[RR, bytes]],
        extra: ExtraSections,
    ):
        self.id_flags = id_flags
        self.question = question
        self.answer = answer
        self.extra = extra

    def walk(self):
        for obj in self.id_flags.walk():
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
        for obj in self.extra:
            yield obj

    def to_obj(self) -> list:
        res = self.id_flags.to_obj()
        if self.question:
            res.append(self.question)
        res.append(self.answer)
        res.extend(self.extra.to_obj())
        return res


class DefaultPackingTableConstructor:
    def __init__(self, encoder):
        self.encoder = encoder

    def get_packing_table(self, obj):
        pass


class Encoder:
    packing_table_constructor_type = DefaultPackingTableConstructor

    def __init__(self, fp, packed=False):
        self.fp = fp
        self.packed = packed
        self.cbor_encoder = self.cbor_encoder_factory(
            packed, fp=fp, default=self.default_encoder
        )
        if self.packed:
            self.tries = {
                str: trie.CountingStringTrie(),
                bytes: trie.CountingBytesTrie(),
            }
            self.packing_table = None
        else:
            self.tries = None
            self.packing_table = None

    def cbor_encoder_factory(self, packed, *args, **kwargs):
        outer = self

        class PackedCBOREncoder(cbor2.CBOREncoder):
            def _ref_shared_item(self, value, idx):
                if idx < 16:
                    self.encode_simple_value(idx)
                else:
                    n = (15 - idx) // 2 if idx % 2 else (idx - 16) // 2
                    self.encode_semantic(cbor2.CBORTag(6, n))

            def _ref_straight_rump(self, value, idx):
                if idx == 0:
                    self.encode_semantic(cbor2.CBORTag(6, value))
                elif idx < 32:
                    self.encode_semantic(cbor2.CBORTag(224 + idx, value))
                elif idx < 4096:
                    self.encode_semantic(
                        cbor2.CBORTag(28704 + (idx - 32), value)
                    )
                elif idx < (1 << 28):
                    self.encode_semantic(
                        cbor2.CBORTag(1879052288 + (idx - 4096), value)
                    )
                else:  # pragma: no-cover
                    raise RuntimeError("Should not be reached")

            def _ref_inverted_rump(self, value, idx):
                if idx < 8:
                    self.encode_semantic(cbor2.CBORTag(216 + idx, value))
                elif idx < 1024:
                    self.encode_semantic(
                        cbor2.CBORTag(27647 + (idx - 8), value)
                    )
                elif idx < (1 << 26):
                    self.encode_semantic(
                        cbor2.CBORTag(1811940352 + (idx - 1024), value)
                    )
                else:  # pragma: no-cover
                    raise RuntimeError("Should not be reached")

            def encode_int(self, value):
                if outer.packing_table:
                    for idx, prefix in enumerate(outer.packing_table):
                        if isinstance(prefix, int) and value == prefix:
                            self._ref_shared_item(value, idx)
                            return
                super().encode_int(value)

            def encode_bytestring(self, value):
                if outer.packing_table:
                    for idx, prefix in enumerate(outer.packing_table):
                        if isinstance(prefix, bytes) and value == prefix:
                            self._ref_shared_item(value, idx)
                            return
                        elif value.startswith(prefix):
                            value = value[len(prefix):]
                            self._ref_straight_rump(value, idx)
                            return
                super().encode_bytestring(value)

            def encode_string(self, value):
                if outer.packing_table:
                    for idx, suffix in enumerate(outer.packing_table):
                        if isinstance(suffix, str) and value == suffix:
                            self._ref_shared_item(value, idx)
                            return
                        elif value.endswith(suffix):
                            value = value[:-len(suffix)]
                            self._ref_inverted_rump(value, idx)
                            return
                super().encode_string(value)

        if packed:
            return PackedCBOREncoder(*args, **kwargs)
        return cbor2.CBOREncoder(*args, **kwargs)

    @staticmethod
    def default_encoder(cbor_encoder, value):
        if isinstance(value, (DNSQuery, DNSResponse, Question, RR)):
            cbor_encoder.encode(value.to_obj())
        elif isinstance(value, dns.name.Name):
            cbor_encoder.encode(value.to_text(omit_final_dot=True))
        else:
            raise ValueError(f"Can not encode {value:r} (type {type(value)})")

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
        additional = RR.rrs_from_section(msg.additional, question, self.tries)
        if msg.opt:
            additional += RR.rrs_from_section([msg.opt], question, self.tries)
        if msg.tsig:
            additional += RR.rrs_from_section(msg.tsig, question, self.tries)
        return additional

    def _encode_query(self, msg: dns.message.Message):
        question = self._get_question(msg)
        return DNSQuery(
            QueryIDFlags(msg.id, msg.flags),
            question,
            ExtraSections(
                authority=RR.rrs_from_section(msg.authority, question, self.tries),
                additional=self._get_additional(msg, question),
            ),
        )

    def _encode_response(
        self,
        msg: dns.message.Message,
        orig_question: Optional[Question]
    ):
        question = self._get_question(msg)
        if orig_question and question == orig_question:
            question = None
        elif self.tries:
            self.tries[str].insert(question.name.to_text(omit_final_dot=True)[::-1])
        return DNSResponse(
            ResponseIDFlags(msg.id, msg.flags),
            question,
            RR.rrs_from_section(msg.answer, orig_question or question, self.tries),
            ExtraSections(
                authority=RR.rrs_from_section(msg.authority, orig_question or question,
                                              self.tries),
                additional=self._get_additional(msg, orig_question or question),
            ),
        )

    def encode(
        self,
        msg: Union[bytes, dns.message.Message],
        orig_query: Optional[Union[bytes, list]] = None
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
        else:
            res = self._encode_query(msg)
        if self.packed:
            # TODO: Henne-Ei-Problem :(
            packing_table_constr = self.packing_table_constructor_type(self)
            self.packing_table = packing_table_constr.get_packing_table(res)
        self.cbor_encoder.encode(res)
