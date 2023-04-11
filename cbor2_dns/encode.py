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
    ):
        if ttl < 0:
            raise ValueError(f"ttl={ttl} must not be < 0")
        super().__init__(type_spec)
        self.question = question
        self.name = name
        self.ttl = ttl
        self.rdata = rdata

    def to_obj(self) -> list:
        res = []
        if self.question.name != self.name:
            res.append(self.name)
        res.append(self.ttl)
        res.extend(self.type_spec.to_obj())
        if self.rdata.rdtype in TEXT_STRING_TYPES:
            res.append(self.rdata.to_text().strip("."))
        else:
            res.append(self.rdata.to_wire())
        return res

    @staticmethod
    def rrs_from_rrset(rrset, question: Question) -> list:
        if isinstance(rrset, dns.rrset.RRset):
            if rrset.rdtype in [RdataType.OPT, RdataType.TSIG]:
                with io.BytesIO() as fp:
                    rrset.to_wire(fp)
                    return [fp.getvalue()]
            return [
                RR(
                    rrset.name,
                    TypeSpec(rrset.rdtype, rrset.rdclass),
                    rrset.ttl,
                    rr,
                    question,
                )
                for rr in rrset
            ]
        else:
            return [rrset.to_wire()]

    @staticmethod
    def rrs_from_section(section: List, question: Question) -> list:
        return list(
            itertools.chain.from_iterable(
                RR.rrs_from_rrset(rrset, question)
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

    def to_obj(self) -> list:
        if self.authority:
            return [self.authority, self.additional]
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
        id_flags: QueryIDFlags,
        question: Optional[Question],
        answer: List[Union[RR, bytes]],
        extra: ExtraSections,
    ):
        self.id_flags = id_flags
        self.question = question
        self.answer = answer
        self.extra = extra

    def to_obj(self) -> list:
        res = self.id_flags.to_obj()
        if self.question:
            res.append(self.question)
        res.append(self.answer)
        res.extend(self.extra.to_obj())
        return res


class DefaultPackingTableConstructor:
    def __init__(self):
        pass

    """TODO packing table length should not exceed 2^26"""


class Encoder:
    def __init__(self, fp, packed=False):
        self.fp = fp
        self.cbor_encoder = self.cbor_encoder_factory(
            fp=fp, default=self.default_encoder
        )
        self.packed = packed
        self.packing_table = None

    def cbor_encoder_factory(self, *args, **kwargs):
        outer = self

        class CBOREncoder(cbor2.CBOREncoder):
            def _ref_shared_item(self, value, idx):
                if idx < 16:
                    self.encode_simple_value(idx)
                else:
                    n = (15 - idx) // 2 if idx % 2 else (idx - 16) // 2
                    self.encode_semantic(CBORTag(6, n))

            def _ref_straight_rump(self, value, idx):
                if idx == 0:
                    self.encode_semantic(CBORTag(6, value))
                elif idx < 32:
                    self.encode_semantic(CBORTag(224 + idx, value))
                elif idx < 4096:
                    self.encode_semantic(
                        CBORTag(28704 + (idx - 32), value)
                    )
                elif idx < (1 << 28):
                    self.encode_semantic(
                        CBORTag(1879052288 + (idx - 4096), value)
                    )
                else:  # pragma: no-cover
                    raise RuntimeError("Should not be reached")


            def _ref_inverted_rump(self, value, idx):
                if idx < 8:
                    self.encode_semantic(CBORTag(216 + idx, value))
                elif idx < 1024:
                    self.encode_semantic(
                        CBORTag(27647 + (idx - 8), value)
                    )
                elif idx < (1 << 26):
                    self.encode_semantic(
                        CBORTag(1811940352 + (idx - 1024), value)
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
                        if isinstance(prefix, str) and value == suffix:
                            self._ref_shared_item(value, idx)
                            return
                        elif value.endswith(suffix):
                            value = value[:-len(suffix)]
                            self._ref_inverted_rump(value, idx)
                            return
                super().encode_string(value)

        return CBOREncoder(*args, **kwargs)

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

    @staticmethod
    def _get_additional(msg, question):
        additional = RR.rrs_from_section(msg.additional, question)
        if msg.opt:
            additional += RR.rrs_from_section([msg.opt], question)
        if msg.tsig:
            additional += RR.rrs_from_section(msg.tsig, question)
        return additional

    def _encode_query(self, msg: dns.message.Message):
        question = self._get_question(msg)
        return DNSQuery(
            QueryIDFlags(msg.id, msg.flags),
            question,
            ExtraSections(
                authority=RR.rrs_from_section(msg.authority, question),
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
        return DNSResponse(
            QueryIDFlags(msg.id, msg.flags),
            question,
            RR.rrs_from_section(msg.answer, orig_question or question),
            ExtraSections(
                authority=RR.rrs_from_section(msg.authority, orig_question or question),
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
            # TODO
            pass
        self.cbor_encoder.encode(res)
