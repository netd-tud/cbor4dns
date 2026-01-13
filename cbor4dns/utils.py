"""
Provides utilities for de- and encoding DNS messages from and to application/dns+cbor
"""

from typing import Union

import cbor2
import dns.name


_escaped_text = '"().;\\@$'


def _escapify(label: Union[bytes, str]) -> str:
    if isinstance(label, bytes):
        return label.decode("utf-8")
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


def name_to_labels(name):
    if len(name.labels) == 0:
        return "@"
    if len(name.labels) == 1 and name.labels[0] == b"":
        return "."
    if name.is_absolute():
        labels = name.labels[:-1]
    else:
        labels = name.labels
    return [IDNA_CODEC.decode(x) for x in labels]


class RefIdx:
    class Reference:
        def __init__(self, idx, A=16):
            self.idx = idx
            self.A = A

        def create(self, offset=0):
            idx = self.idx + offset
            if idx < self.A:
                return cbor2.CBORSimpleValue(idx)
            n = (idx - self.A) // 2 if idx % 2 else ((self.A - idx - 1) // 2)
            return cbor2.CBORTag(6, n)

    def __init__(self, A=16):
        self.A = A

        self._dict = {}

    def __len__(self):
        return len(self._dict)

    def shared_item(self, idx):
        return self.Reference(idx, A=self.A)

    def add(self, name):
        comps = name_to_labels(name)
        res = []
        for i, comp in enumerate(comps):
            suffix = tuple(comps[i:])
            if suffix in self._dict:
                res.append(self.shared_item(self._dict[suffix]))
                break
            else:
                self._dict[suffix] = len(self)
                res.append(comp)
        return res

    def clear(self):
        self._dict.clear()


"""
https://web.archive.org/web/20150226083354/http://leetcode.com/2011/08/reverse-bits.html
"""


def reverse_u16(x):
    assert x <= 0xFFFF
    x = ((x & 0x5555) << 1) | ((x & 0xAAAA) >> 1)
    x = ((x & 0x3333) << 2) | ((x & 0xCCCC) >> 2)
    x = ((x & 0x0F0F) << 4) | ((x & 0xF0F0) >> 4)
    x = ((x & 0x00FF) << 8) | ((x & 0xFF00) >> 8)
    return x
