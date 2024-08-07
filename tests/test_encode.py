# pylint: disable=missing-function-docstring,missing-module-docstring


import io
import pprint

import cbor2
import pytest

import cbor4dns.encode

QUERY_AAAA = (
    b"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x01\x07\x65\x78\x61"
    b"\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x00\x1c\x00\x01\x00\x00\x29"
    b"\x04\xd0\x00\x00\x00\x00\x00\x0c\x00\x0a\x00\x08\x99\x21\x09\x65"
    b"\x33\xa3\x66\xb5"
)
QUERY_AAAA_CBOR = (
    b"\x83\x19\x01 \x81kexample.org\x81\xd8\x8d\x82\x19\x04\xd0"
    b"\x82\nH\x99!\te3\xa3f\xb5"
    if cbor4dns.encode.RR.encode_opts
    else b"\x83\x19\x01 \x81kexample.org\x81W\x00\x00)\x04"
    b"\xd0\x00\x00\x00\x00\x00\x0c\x00\n\x00\x08\x99!\te3\xa3f\xb5"
)
QUERY_A = (
    b"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x01\x07\x65\x78\x61"
    b"\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x00\x01\x00\x01\x00\x00\x29"
    b"\x04\xd0\x00\x00\x00\x00\x00\x0c\x00\x0a\x00\x08\x74\x5e\x6c\x10"
    b"\xa8\x46\x19\xa4"
)
QUERY_A_CBOR = (
    b"\x83\x19\x01 \x82kexample.org\x01\x81\xd8\x8d\x82\x19\x04\xd0"
    b"\x82\nHt^l\x10\xa8F\x19\xa4"
    if cbor4dns.encode.RR.encode_opts
    else b"\x83\x19\x01 \x82kexample.org\x01\x81W\x00\x00)\x04"
    b"\xd0\x00\x00\x00\x00\x00\x0c\x00\n\x00\x08t^l\x10\xa8F\x19\xa4"
)
RESPONSE_AAAA = (
    b"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x06\x00\x0d\x07\x65\x78\x61"
    b"\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x00\x1c\x00\x01\xc0\x0c\x00"
    b"\x1c\x00\x01\x00\x00\x59\x51\x00\x10\x26\x06\x28\x00\x02\x20\x00"
    b"\x01\x02\x48\x18\x93\x25\xc8\x19\x46\xc0\x14\x00\x02\x00\x01\x00"
    b"\x01\xb1\xf0\x00\x15\x02\x64\x30\x03\x6f\x72\x67\x0b\x61\x66\x69"
    b"\x6c\x69\x61\x73\x2d\x6e\x73\x74\xc0\x14\xc0\x14\x00\x02\x00\x01"
    b"\x00\x01\xb1\xf0\x00\x05\x02\x62\x30\xc0\x48\xc0\x14\x00\x02\x00"
    b"\x01\x00\x01\xb1\xf0\x00\x05\x02\x62\x32\xc0\x48\xc0\x14\x00\x02"
    b"\x00\x01\x00\x01\xb1\xf0\x00\x19\x02\x63\x30\x03\x6f\x72\x67\x0b"
    b"\x61\x66\x69\x6c\x69\x61\x73\x2d\x6e\x73\x74\x04\x69\x6e\x66\x6f"
    b"\x00\xc0\x14\x00\x02\x00\x01\x00\x01\xb1\xf0\x00\x05\x02\x61\x30"
    b"\xc0\x8b\xc0\x14\x00\x02\x00\x01\x00\x01\xb1\xf0\x00\x05\x02\x61"
    b"\x32\xc0\x8b\xc0\xad\x00\x01\x00\x01\x00\x01\xb1\xf0\x00\x04\xc7"
    b"\x13\x38\x01\xc0\xbe\x00\x01\x00\x01\x00\x01\xb1\xf0\x00\x04\xc7"
    b"\xf9\x70\x01\xc0\x66\x00\x01\x00\x01\x00\x01\xb1\xf0\x00\x04\xc7"
    b"\x13\x36\x01\xc0\x77\x00\x01\x00\x01\x00\x01\xb1\xf0\x00\x04\xc7"
    b"\xf9\x78\x01\xc0\x88\x00\x01\x00\x01\x00\x01\xb1\xf0\x00\x04\xc7"
    b"\x13\x35\x01\xc0\x45\x00\x01\x00\x01\x00\x01\xb1\xf0\x00\x04\xc7"
    b"\x13\x39\x01\xc0\xad\x00\x1c\x00\x01\x00\x01\xb1\xf0\x00\x10\x20"
    b"\x01\x05\x00\x00\x0e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xc0"
    b"\xbe\x00\x1c\x00\x01\x00\x01\xb1\xf0\x00\x10\x20\x01\x05\x00\x00"
    b"\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xc0\x66\x00\x1c\x00"
    b"\x01\x00\x01\xb1\xf0\x00\x10\x20\x01\x05\x00\x00\x0c\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x01\xc0\x77\x00\x1c\x00\x01\x00\x01\xb1"
    b"\xf0\x00\x10\x20\x01\x05\x00\x00\x48\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x01\xc0\x88\x00\x1c\x00\x01\x00\x01\xb1\xf0\x00\x10\x20"
    b"\x01\x05\x00\x00\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xc0"
    b"\x45\x00\x1c\x00\x01\x00\x01\xb1\xf0\x00\x10\x20\x01\x05\x00\x00"
    b"\x0f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x29\x10\x00"
    b"\x00\x00\x00\x00\x00\x1c\x00\x0a\x00\x18\x16\x19\xc4\x7f\x6e\xd6"
    b"\xc4\xab\xef\xec\xe8\x79\x64\x35\x46\xd3\x7b\x9c\xb7\xd5\x61\xaa"
    b"\xd9\xc2"
)
RESPONSE_AAAA_CBOR = (
    b"\x85\x19\x81\x80\x81kexample.org\x81\x82\x19YQP&\x06(\x00\x02 "
    b"\x00\x01\x02H\x18\x93%\xc8\x19F\x86\x84corg\x1a\x00\x01\xb1\xf0\x02vd0.or"
    b"g.afilias-nst.org\x84corg\x1a\x00\x01\xb1\xf0\x02vb0.org.afilias-nst.org\x84"
    b"corg\x1a\x00\x01\xb1\xf0\x02vb2.org.afilias-nst.org\x84corg\x1a\x00"
    b"\x01\xb1\xf0\x02wc0.org.afilias-nst.info\x84corg\x1a\x00\x01\xb1\xf0\x02w"
    b"a0.org.afilias-nst.info\x84corg\x1a\x00\x01\xb1\xf0\x02wa2.org.afilias-ns"
    b"t.info\x8d\x84wa0.org.afilias-nst.info\x1a\x00\x01\xb1\xf0\x01D\xc7"
    b"\x138\x01\x84wa2.org.afilias-nst.info\x1a\x00\x01\xb1\xf0\x01D\xc7"
    b"\xf9p\x01\x84vb0.org.afilias-nst.org\x1a\x00\x01\xb1\xf0\x01D\xc7\x13"
    b"6\x01\x84vb2.org.afilias-nst.org\x1a\x00\x01\xb1\xf0\x01D\xc7\xf9x\x01\x84wc"
    b"0.org.afilias-nst.info\x1a\x00\x01\xb1\xf0\x01D\xc7\x135\x01\x84vd0.org.af"
    b"ilias-nst.org\x1a\x00\x01\xb1\xf0\x01D\xc7\x139\x01\x83wa0.org.afilias-nst"
    b".info\x1a\x00\x01\xb1\xf0P \x01\x05\x00\x00\x0e\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x01\x83wa2.org.afilias-nst.info\x1a\x00\x01\xb1\xf0P \x01"
    b"\x05\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x83vb0.org.afilias-n"
    b"st.org\x1a\x00\x01\xb1\xf0P \x01\x05\x00\x00\x0c\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x01\x83vb2.org.afilias-nst.org\x1a\x00\x01\xb1\xf0P \x01"
    b"\x05\x00\x00H\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x83wc0.org.afilias-n"
    b"st.info\x1a\x00\x01\xb1\xf0P \x01\x05\x00\x00\x0b\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x01\x83vd0.org.afilias-nst.org\x1a\x00\x01\xb1\xf0P "
    b"\x01\x05\x00\x00\x0f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xd8\x8d"
    b"\x82\x19\x10\x00\x82\nX\x18\x16\x19\xc4\x7fn\xd6\xc4\xab\xef\xec\xe8yd5F"
    b"\xd3{\x9c\xb7\xd5a\xaa\xd9\xc2"
    if cbor4dns.encode.RR.encode_opts
    else b"\x85\x19\x81\x80\x81kexample.org\x81\x82\x19YQP&\x06(\x00\x02 "
    b"\x00\x01\x02H\x18\x93%\xc8\x19F\x86\x84corg\x1a\x00\x01\xb1\xf0\x02vd0.or"
    b"g.afilias-nst.org\x84corg\x1a\x00\x01\xb1\xf0\x02vb0.org.afilias-nst.org\x84"
    b"corg\x1a\x00\x01\xb1\xf0\x02vb2.org.afilias-nst.org\x84corg\x1a\x00"
    b"\x01\xb1\xf0\x02wc0.org.afilias-nst.info\x84corg\x1a\x00\x01\xb1\xf0\x02w"
    b"a0.org.afilias-nst.info\x84corg\x1a\x00\x01\xb1\xf0\x02wa2.org.afilias-ns"
    b"t.info\x8d\x84wa0.org.afilias-nst.info\x1a\x00\x01\xb1\xf0\x01D\xc7"
    b"\x138\x01\x84wa2.org.afilias-nst.info\x1a\x00\x01\xb1\xf0\x01D\xc7"
    b"\xf9p\x01\x84vb0.org.afilias-nst.org\x1a\x00\x01\xb1\xf0\x01D\xc7\x13"
    b"6\x01\x84vb2.org.afilias-nst.org\x1a\x00\x01\xb1\xf0\x01D\xc7\xf9x\x01\x84wc"
    b"0.org.afilias-nst.info\x1a\x00\x01\xb1\xf0\x01D\xc7\x135\x01\x84vd0.org.af"
    b"ilias-nst.org\x1a\x00\x01\xb1\xf0\x01D\xc7\x139\x01\x83wa0.org.afilias-nst"
    b".info\x1a\x00\x01\xb1\xf0P \x01\x05\x00\x00\x0e\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x01\x83wa2.org.afilias-nst.info\x1a\x00\x01\xb1\xf0P \x01"
    b"\x05\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x83vb0.org.afilias-n"
    b"st.org\x1a\x00\x01\xb1\xf0P \x01\x05\x00\x00\x0c\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x01\x83vb2.org.afilias-nst.org\x1a\x00\x01\xb1\xf0P \x01"
    b"\x05\x00\x00H\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x83wc0.org.afilias-n"
    b"st.info\x1a\x00\x01\xb1\xf0P \x01\x05\x00\x00\x0b\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x01\x83vd0.org.afilias-nst.org\x1a\x00\x01\xb1\xf0P "
    b"\x01\x05\x00\x00\x0f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01X'\x00\x00)"
    b"\x10\x00\x00\x00\x00\x00\x00\x1c\x00\n\x00\x18\x16\x19\xc4\x7fn\xd6\xc4\xab"
    b"\xef\xec\xe8yd5F\xd3{\x9c\xb7\xd5a\xaa\xd9\xc2"
)
RESPONSE_A = (
    b"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x01\x07\x65\x78\x61"
    b"\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x00\x1c\x00\x01\x00\x00\x29"
    b"\x04\xd0\x00\x00\x00\x00\x00\x0c\x00\x0a\x00\x08\x99\x21\x09\x65"
    b"\x33\xa3\x66\xb5"
)


TEST_VECTOR = (
    pytest.param(
        QUERY_AAAA,
        True,
        None,
        False,
        QUERY_AAAA_CBOR,
        id="query example.org AAAA",
    ),
    pytest.param(
        QUERY_A,
        True,
        None,
        False,
        QUERY_A_CBOR,
        id="query example.org A",
    ),
    pytest.param(
        RESPONSE_AAAA,
        False,
        None,
        False,
        RESPONSE_AAAA_CBOR,
        id="response example.org AAAA (w/o original query)",
    ),
    pytest.param(
        RESPONSE_AAAA,
        False,
        QUERY_AAAA_CBOR,
        False,
        (
            b"\x84\x19\x81\x80\x81\x82\x19YQP&\x06(\x00\x02 \x00\x01\x02H\x18"
            b"\x93%\xc8\x19F\x86\x84corg\x1a\x00\x01\xb1\xf0\x02vd0.org.afilias-nst.org"
            b"\x84corg\x1a\x00\x01\xb1\xf0\x02vb0.org.afilias-nst.org\x84corg\x1a\x00"
            b"\x01\xb1\xf0\x02vb2.org.afilias-nst.org\x84corg\x1a\x00\x01\xb1\xf0\x02"
            b"wc0.org.afilias-nst.info\x84corg\x1a\x00\x01\xb1\xf0\x02wa0.org."
            b"afilias-nst.info\x84corg\x1a\x00\x01\xb1\xf0\x02wa2.org.afilias-nst.info"
            b"\x8d\x84wa0.org.afilias-nst.info\x1a\x00\x01\xb1\xf0\x01D\xc7\x138\x01"
            b"\x84wa2.org.afilias-nst.info\x1a\x00\x01\xb1\xf0\x01D\xc7\xf9p\x01\x84"
            b"vb0.org.afilias-nst.org\x1a\x00\x01\xb1\xf0\x01D\xc7\x136\x01\x84vb2.org."
            b"afilias-nst.org\x1a\x00\x01\xb1\xf0\x01D\xc7\xf9x\x01\x84wc0.org."
            b"afilias-nst.info\x1a\x00\x01\xb1\xf0\x01D\xc7\x135\x01\x84vd0.org."
            b"afilias-nst.org\x1a\x00\x01\xb1\xf0\x01D\xc7\x139\x01\x83wa0.org."
            b"afilias-nst.info\x1a\x00\x01\xb1\xf0P \x01\x05\x00\x00\x0e\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x01\x83wa2.org.afilias-nst.info\x1a\x00\x01\xb1"
            b"\xf0P \x01\x05\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x83"
            b"vb0.org.afilias-nst.org\x1a\x00\x01\xb1\xf0P \x01\x05\x00\x00\x0c\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x01\x83vb2.org.afilias-nst.org\x1a\x00\x01"
            b"\xb1\xf0P \x01\x05\x00\x00H\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x83"
            b"wc0.org.afilias-nst.info\x1a\x00\x01\xb1\xf0P \x01\x05\x00\x00\x0b\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x01\x83vd0.org.afilias-nst.org\x1a\x00"
            b"\x01\xb1\xf0P \x01\x05\x00\x00\x0f\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x01\xd8\x8d\x82\x19\x10\x00\x82\nX\x18\x16\x19\xc4\x7fn\xd6\xc4\xab\xef"
            b"\xec\xe8yd5F\xd3{\x9c\xb7\xd5a\xaa\xd9\xc2"
            if cbor4dns.encode.RR.encode_opts
            else b"\x84\x19\x81\x80\x81\x82\x19YQP&\x06(\x00\x02 \x00\x01\x02H\x18"
            b"\x93%\xc8\x19F\x86\x84corg\x1a\x00\x01\xb1\xf0\x02vd0.org.afilias-nst.org"
            b"\x84corg\x1a\x00\x01\xb1\xf0\x02vb0.org.afilias-nst.org\x84corg\x1a"
            b"\x00\x01\xb1\xf0\x02vb2.org.afilias-nst.org\x84corg\x1a\x00\x01\xb1\xf0"
            b"\x02wc0.org.afilias-nst.info\x84corg\x1a\x00\x01\xb1\xf0\x02wa0.org."
            b"afilias-nst.info\x84corg\x1a\x00\x01\xb1\xf0\x02wa2.org.afilias-nst.info"
            b"\x8d\x84wa0.org.afilias-nst.info\x1a\x00\x01\xb1\xf0\x01D\xc7\x138\x01"
            b"\x84wa2.org.afilias-nst.info\x1a\x00\x01\xb1\xf0\x01D\xc7\xf9p\x01\x84"
            b"vb0.org.afilias-nst.org\x1a\x00\x01\xb1\xf0\x01D\xc7\x136\x01\x84vb2.org."
            b"afilias-nst.org\x1a\x00\x01\xb1\xf0\x01D\xc7\xf9x\x01\x84wc0.org."
            b"afilias-nst.info\x1a\x00\x01\xb1\xf0\x01D\xc7\x135\x01\x84vd0.org."
            b"afilias-nst.org\x1a\x00\x01\xb1\xf0\x01D\xc7\x139\x01\x83wa0.org."
            b"afilias-nst.info\x1a\x00\x01\xb1\xf0P \x01\x05\x00\x00\x0e\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x01\x83wa2.org.afilias-nst.info\x1a\x00\x01\xb1"
            b"\xf0P \x01\x05\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x83vb0."
            b"org.afilias-nst.org\x1a\x00\x01\xb1\xf0P \x01\x05\x00\x00\x0c\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x01\x83vb2.org.afilias-nst.org\x1a\x00\x01\xb1"
            b"\xf0P \x01\x05\x00\x00H\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x83wc0."
            b"org.afilias-nst.info\x1a\x00\x01\xb1\xf0P \x01\x05\x00\x00\x0b\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x01\x83vd0.org.afilias-nst.org\x1a\x00\x01"
            b"\xb1\xf0P \x01\x05\x00\x00\x0f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01X'"
            b"\x00\x00)\x10\x00\x00\x00\x00\x00\x00\x1c\x00\n\x00\x18\x16\x19\xc4\x7f"
            b"n\xd6\xc4\xab\xef\xec\xe8yd5F\xd3{\x9c\xb7\xd5a\xaa\xd9\xc2"
        ),
        id="response example.org AAAA (w/ original query)",
    ),
    pytest.param(
        QUERY_AAAA,
        True,
        None,
        True,
        QUERY_AAAA_CBOR,
        id="query example.org AAAA, packed",
    ),
    pytest.param(
        QUERY_A,
        True,
        None,
        True,
        QUERY_A_CBOR,
        id="query example.org A, packed",
    ),
    pytest.param(
        RESPONSE_AAAA,
        False,
        None,
        True,
        (
            b"\x82\x90\x1a\x00\x01\xb1\xf0corgu.org.afilias-nst.info\xd8\xd9q.org."
            b"afilias-nst.\xd8\xdaa0\xd8\xdba0E \x01\x05\x00\x00A\xc7\xd8\xe7A\x13\xd8"
            b"\xdaba2\xd8\xdcac\xd8\xdcaa\xd8\xdbbb2\xd8\xddad\xd8\xddab\xd8\xe7A\xf9"
            b"\x85\x19\x81\x80\x81\xd8\xd9hexample.\x81\x82\x19YQP&\x06(\x00\x02 \x00"
            b"\x01\x02H\x18\x93%\xc8\x19F\x86\x84\xe1\xe0\x02\xed\x84\xe1\xe0\x02\xee"
            b"\x84\xe1\xe0\x02\xec\x84\xe1\xe0\x02\xea\x84\xe1\xe0\x02\xeb\x84"
            b"\xe1\xe0\x02\xe9\x8d\x84\xeb\xe0\x01\xd8\xe8B8\x01\x84\xe9\xe0\x01\xd8"
            b"\xefBp\x01\x84\xee\xe0\x01\xd8\xe8B6\x01\x84\xec\xe0\x01\xd8\xefBx"
            b"\x01\x84\xea\xe0\x01\xd8\xe8B5\x01\x84\xed\xe0\x01\xd8\xe8B9\x01\x83"
            b"\xeb\xe0\xd8\xe6K\x0e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
            b"\x83\xe9\xe0\xd8\xe6K@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x83\xee"
            b"\xe0\xd8\xe6K\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x83\xec\xe0\xd8"
            b"\xe6KH\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x83\xea\xe0\xd8\xe6K\x0b"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x83\xed\xe0\xd8\xe6K\x0f\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x01\xd8\x8d\x82\x19\x10\x00\x82\nX\x18"
            b"\x16\x19\xc4\x7fn\xd6\xc4\xab\xef\xec\xe8yd5F\xd3{\x9c\xb7\xd5a\xaa\xd9"
            b"\xc2"
            if cbor4dns.encode.RR.encode_opts
            else b"\x82\x91\x1a\x00\x01\xb1\xf0corgu.org.afilias-nst.info\xd8\xd9q.org."
            b"afilias-nst.E \x01\x05\x00\x00\xd8\xdaa0\xd8\xdba0A\xc7\xd8\xe7A\x13\xd8"
            b"\xdaba2\xd8\xddac\xd8\xddaa\xd8\xdbbb2\xd8\xdead\xd8\xdeab\xd8\xe4K\x0f"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xd8\xe7A\xf9\x85\x19\x81\x80"
            b"\x81\xd8\xd9hexample.\x81\x82\x19YQP&\x06(\x00\x02 \x00\x01\x02H"
            b"\x18\x93%\xc8\x19F\x86\x84\xe1\xe0\x02\xed\x84\xe1\xe0\x02\xee\x84\xe1"
            b"\xe0\x02\xec\x84\xe1\xe0\x02\xea\x84\xe1\xe0\x02\xeb\x84\xe1\xe0\x02"
            b"\xe9\x8d\x84\xeb\xe0\x01\xd8\xe8B8\x01\x84\xe9\xe0\x01\xd8\xf0Bp\x01"
            b"\x84\xee\xe0\x01\xd8\xe8B6\x01\x84\xec\xe0\x01\xd8\xf0Bx\x01\x84\xea"
            b"\xe0\x01\xd8\xe8B5\x01\x84\xed\xe0\x01\xd8\xe8B9\x01\x83\xeb\xe0\xd8"
            b"\xe4K\x0e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x83\xe9\xe0\xd8\xe4K@"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x83\xee\xe0\xd8\xe4K"
            b"\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x83\xec\xe0\xd8\xe4KH\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x01\x83\xea\xe0\xd8\xe4K\x0b\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x01\x83\xed\xe0\xefX'\x00\x00)\x10\x00"
            b"\x00\x00\x00\x00\x00\x1c\x00\n\x00\x18\x16\x19\xc4\x7fn\xd6\xc4\xab\xef"
            b"\xec\xe8yd5F\xd3{\x9c\xb7\xd5a\xaa\xd9\xc2"
        ),
        id="response example.org AAAA (w/o original query), packed",
    ),
    pytest.param(
        RESPONSE_AAAA,
        False,
        QUERY_AAAA_CBOR,
        True,
        (
            b"\x82\x90\x1a\x00\x01\xb1\xf0corgu.org.afilias-nst.info\xd8\xd9q.org."
            b"afilias-nst.\xd8\xdaa0\xd8\xdba0E \x01\x05\x00\x00A\xc7\xd8\xe7A\x13\xd8"
            b"\xdaba2\xd8\xdcac\xd8\xdcaa\xd8\xdbbb2\xd8\xddad\xd8\xddab\xd8\xe7A\xf9"
            b"\x84\x19\x81\x80\x81\x82\x19YQP&\x06(\x00\x02 \x00\x01\x02H\x18\x93%\xc8"
            b"\x19F\x86\x84\xe1\xe0\x02\xed\x84\xe1\xe0\x02\xee\x84\xe1\xe0\x02"
            b"\xec\x84\xe1\xe0\x02\xea\x84\xe1\xe0\x02\xeb\x84\xe1\xe0\x02\xe9"
            b"\x8d\x84\xeb\xe0\x01\xd8\xe8B8\x01\x84\xe9\xe0\x01\xd8\xefBp\x01\x84"
            b"\xee\xe0\x01\xd8\xe8B6\x01\x84\xec\xe0\x01\xd8\xefBx\x01\x84\xea\xe0"
            b"\x01\xd8\xe8B5\x01\x84\xed\xe0\x01\xd8\xe8B9\x01\x83\xeb\xe0\xd8\xe6"
            b"K\x0e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x83\xe9\xe0\xd8\xe6K@\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x01\x83\xee\xe0\xd8\xe6K\x0c"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x83\xec\xe0\xd8\xe6KH\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x01\x83\xea\xe0\xd8\xe6K\x0b\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x01\x83\xed\xe0\xd8\xe6K\x0f\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x01\xd8\x8d\x82\x19\x10\x00\x82\nX\x18\x16"
            b"\x19\xc4\x7fn\xd6\xc4\xab\xef\xec\xe8yd5F\xd3{\x9c\xb7\xd5a\xaa\xd9\xc2"
            if cbor4dns.encode.RR.encode_opts
            else b"\x82\x91\x1a\x00\x01\xb1\xf0corgu.org.afilias-nst.info\xd8\xd9q.org."
            b"afilias-nst.E \x01\x05\x00\x00\xd8\xdaa0\xd8\xdba0A\xc7\xd8\xe7A\x13\xd8"
            b"\xdaba2\xd8\xddac\xd8\xddaa\xd8\xdbbb2\xd8\xdead\xd8\xdeab\xd8\xe4K\x0f"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xd8\xe7A\xf9\x84\x19\x81\x80"
            b"\x81\x82\x19YQP&\x06(\x00\x02 \x00\x01\x02H\x18\x93%\xc8\x19F\x86\x84"
            b"\xe1\xe0\x02\xed\x84\xe1\xe0\x02\xee\x84\xe1\xe0\x02\xec\x84\xe1"
            b"\xe0\x02\xea\x84\xe1\xe0\x02\xeb\x84\xe1\xe0\x02\xe9\x8d\x84\xeb"
            b"\xe0\x01\xd8\xe8B8\x01\x84\xe9\xe0\x01\xd8\xf0Bp\x01\x84\xee\xe0\x01"
            b"\xd8\xe8B6\x01\x84\xec\xe0\x01\xd8\xf0Bx\x01\x84\xea\xe0\x01\xd8\xe8"
            b"B5\x01\x84\xed\xe0\x01\xd8\xe8B9\x01\x83\xeb\xe0\xd8\xe4K\x0e\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x01\x83\xe9\xe0\xd8\xe4K@\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x01\x83\xee\xe0\xd8\xe4K\x0c\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x01\x83\xec\xe0\xd8\xe4KH\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x01\x83\xea\xe0\xd8\xe4K\x0b\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x01\x83\xed\xe0\xefX'\x00\x00)\x10\x00\x00\x00\x00\x00"
            b"\x00\x1c\x00\n\x00\x18\x16\x19\xc4\x7fn\xd6\xc4\xab\xef\xec\xe8yd5F\xd3{"
            b"\x9c\xb7\xd5a\xaa\xd9\xc2"
        ),
        id="response example.org AAAA (w/ original query), packed",
    ),
    pytest.param(
        bytes.fromhex("00000100000100000000000007736f6c2d646f630378797a0000300001"),
        True,
        None,
        False,
        b"\x82\x19\x01\x00\x82ksol-doc.xyz\x180",
    ),
    pytest.param(
        bytes.fromhex(
            "00008180000100020000000003366e7702696d0000020001c00c000200010000546000180"
            "4656c6c65026e730a636c6f7564666c61726503636f6d00c00c0002000100005460000603"
            "6a696dc029"
        ),
        False,
        b"\x82\x19\x01\x00\x82ksol-doc.xyz\x180",
        True,
        bytes.fromhex(
            "8284616dd8d8712e6e732e636c6f7564666c6172652e636fd8d865366e772e69195460831"
            "9818082e2028284e2e302d8d964656c6c6584e2e302d8d9636a696d"
        ),
        id="Packed with complicated name structure",
    ),
)


@pytest.mark.parametrize(
    "integer",
    [
        23,
        24,
        255,
        256,
        65535,
        65536,
        4294967295,
        4294967296,
        18446744073709551615,
        18446744073709551616,
        1111111111111111111111111111111111111111111111111111111111111111111,
        -24,
        -25,
        -256,
        -257,
        -65536,
        -65537,
        -4294966296,
        -4294967297,
        -18446744073709551616,
        -18446744073709551617,
        -1111111111111111111111111111111111111111111111111111111111111111111,
    ],
)
def test_cbor_int_length(integer):
    with io.BytesIO() as file:
        cbor_encoder = cbor2.CBOREncoder(file)
        cbor_encoder.encode_int(integer)
        cbor_bytes = file.getvalue()
    assert len(cbor_bytes) == cbor4dns.encode.cbor_int_length(integer)


@pytest.mark.parametrize("wire, _, orig_query, packed, exp_cbor", TEST_VECTOR)
def test_encoder_encode(wire, _, orig_query, packed, exp_cbor):
    with io.BytesIO() as file:
        encoder = cbor4dns.encode.Encoder(
            file, packed=packed, always_omit_question=False
        )
        encoder.encode(wire, orig_query)
        res = file.getvalue()
        pprint.pprint(cbor2.loads(res))
        print(len(res), len(wire), len(res) / len(wire))
        assert res == exp_cbor
