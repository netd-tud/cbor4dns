"""
Provides the encoder for encoding DNS messages to application/dns+cbor
"""

import itertools
from typing import List, Optional, Union

import cbor2
import dns.message
import dns.name
import dns.rrset
from dns.rdataclass import IN, RdataClass
from dns.rdatatype import AAAA, RdataType


class TypeSpec:
    def __init__(self, record_type: RdataType = AAAA, record_class: RdataClass = IN):
        self.record_type = record_type
        self.record_class = record_class

    def to_obj(self) -> list:
        if self.record_class != IN:
            return [self.record_type, self.record_class]
        if self.record_type != AAAA:
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

    def to_obj(self) -> list:
        res = [self.name]
        res.extend(self.type_spec.to_obj())
        return res


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
        res.append(self.rdata)
        return res

    @staticmethod
    def rrs_from_rrset(rrset, question: Question) -> list:
        if isinstance(rrset, dns.rrset.RRset):
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
            # TODO: some info for options is lost here, other cases need to be evaluated
            # as well...
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
            return [self.additional, self.authority]
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


class Encoder:
    def __init__(self, fp, packed=False, enforce_id0=False):
        self.fp = fp
        self.cbor_encoder = cbor2.CBOREncoder(fp=fp, default=self.default_encoder)

    @staticmethod
    def default_encoder(cbor_encoder, value):
        if isinstance(value, (DNSQuery, Question)):
            cbor_encoder.encode(value.to_obj())
        elif isinstance(value, dns.name.Name):
            cbor_encoder.encode(value.to_text(omit_final_dot=True))
        else:
            print(repr(value))

    def encode(self, msg, orig_query=None):
        if not isinstance(msg, dns.message.Message):
            msg = dns.message.from_wire(msg)
        if msg.flags & msg.flags.QR:  # msg is response
            pass
        else:
            if len(msg.question) > 1:
                raise ValueError(
                    f"Can not encode query {msg} with question section longer than 1"
                )
            question_section = msg.question[0]
            question = Question(
                question_section.name,
                TypeSpec(question_section.rdtype, question_section.rdclass),
            )
            self.cbor_encoder.encode(
                DNSQuery(
                    QueryIDFlags(msg.id, msg.flags),
                    question,
                    ExtraSections(
                        authority=RR.rrs_from_section(msg.authority, question),
                        additional=(
                            # TODO: find a better solution for this ... :-/
                            RR.rrs_from_section(msg.additional, question) +
                            RR.rrs_from_section(msg.options, question)
                        ),
                    ),
                ),
            )
            print(cbor2.loads(self.fp.getvalue()))
