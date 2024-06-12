"""
Provides utilities for de- and encoding DNS messages from and to application/dns+cbor
"""

"""
https://web.archive.org/web/20150226083354/http://leetcode.com/2011/08/reverse-bits.html
"""

import cbor2


class RefIdx:
    tag = 7

    def __init__(self):
        self._dict = {}
        self._count = 0

    def add(self, name):
        comps = name.split(".")
        res = []
        for i, comp in enumerate(comps):
            suffix = ".".join(comps[i:])
            if suffix in self._dict:
                res.append(cbor2.CBORTag(self.tag, self._dict[suffix]))
                break
            else:
                self._dict[suffix] = self._count
                self._count += 1
                res.append(comp)
        return res

    def clear(self):
        self._dict.clear()
        self._count = 0


def reverse_u16(x):
    assert x <= 0xFFFF
    x = ((x & 0x5555) << 1) | ((x & 0xAAAA) >> 1)
    x = ((x & 0x3333) << 2) | ((x & 0xCCCC) >> 2)
    x = ((x & 0x0F0F) << 4) | ((x & 0xF0F0) >> 4)
    x = ((x & 0x00FF) << 8) | ((x & 0xFF00) >> 8)
    return x
