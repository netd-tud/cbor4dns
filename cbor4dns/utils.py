"""
Provides utilities for de- and encoding DNS messages from and to application/dns+cbor
"""


def reverse_u16(x):
    # see https://web.archive.org/web/20150226083354/http://leetcode.com/2011/08/reverse-bits.html
    assert x <= 0xFFFF
    x = ((x & 0x5555) << 1) | ((x & 0xAAAA) >> 1)
    x = ((x & 0x3333) << 2) | ((x & 0xCCCC) >> 2)
    x = ((x & 0x0F0F) << 4) | ((x & 0xF0F0) >> 4)
    x = ((x & 0x00FF) << 8) | ((x & 0xFF00) >> 8)
    return x
    
