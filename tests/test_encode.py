# pylint: disable=missing-function-docstring,missing-module-docstring


import io

import cbor_diag
import cbor2
import pytest

import cbor4dns.encode

QUERY_AAAA = (
    b"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x01\x07\x65\x78\x61"
    b"\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x00\x1c\x00\x01\x00\x00\x29"
    b"\x04\xd0\x00\x00\x00\x00\x00\x0c\x00\x0a\x00\x08\x99\x21\x09\x65"
    b"\x33\xa3\x66\xb5"
)
QUERY_AAAA_CBOR = """
    [
        288,
        ["example", "org"],
        [141([1232, {10: h'9921096533a366b5'}])],
    ]
    """
QUERY_A = (
    b"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x01\x07\x65\x78\x61"
    b"\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x00\x01\x00\x01\x00\x00\x29"
    b"\x04\xd0\x00\x00\x00\x00\x00\x0c\x00\x0a\x00\x08\x74\x5e\x6c\x10"
    b"\xa8\x46\x19\xa4"
)
QUERY_A_CBOR = """
    [
        288,
        ["example", "org", 1],
        [141([1232, {10: h'745e6c10a84619a4'}])],
    ]
    """
MDNS_QUERY = (
    b"\x00\x00\x00\x00\x00\x01\x00\x02\x00\x00\x00\x00\x0b\x5f\x61\x6d"
    b"\x7a\x6e\x2d\x77\x70\x6c\x61\x79\x04\x5f\x74\x63\x70\x05\x6c\x6f"
    b"\x63\x61\x6c\x00\x00\x0c\x00\x01\xc0\x0c\x00\x0c\x00\x01\x00\x00"
    b"\x0e\x0d\x00\x3f\x3c\x61\x6d\x7a\x6e\x2e\x64\x6d\x67\x72\x3a\x34"
    b"\x35\x37\x45\x46\x39\x30\x43\x31\x34\x43\x31\x41\x35\x34\x39\x33"
    b"\x42\x34\x43\x46\x44\x30\x35\x31\x44\x42\x32\x45\x35\x41\x41\x3a"
    b"\x6a\x50\x57\x50\x54\x75\x79\x65\x2b\x72\x3a\x32\x36\x36\x36\x37"
    b"\x31\xc0\x0c\xc0\x0c\x00\x0c\x00\x01\x00\x00\x11\x94\x00\x3f\x3c"
    b"\x61\x6d\x7a\x6e\x2e\x64\x6d\x67\x72\x3a\x46\x35\x38\x44\x34\x41"
    b"\x33\x39\x31\x43\x37\x44\x36\x45\x45\x43\x36\x44\x45\x34\x31\x37"
    b"\x37\x32\x32\x30\x34\x31\x44\x37\x33\x42\x3a\x43\x4f\x65\x75\x45"
    b"\x4b\x65\x44\x54\x2b\x3a\x34\x37\x35\x37\x38\x34\xc0\x0c"
)
MDNS_QUERY_CBOR = """
[
    ["_amzn-wplay", "_tcp", "local", 12],
    [
        [
            3597,
            12,
            "amzn.dmgr:457EF90C14C1A5493B4CFD051DB2E5AA:jPWPTuye+r:266671",
            7(0),
        ],
        [
            4500,
            12,
            "amzn.dmgr:F58D4A391C7D6EEC6DE417722041D73B:COeuEKeDT+:475784",
            7(0),
        ],
    ],
    [],
    [],
]
"""
RESPONSE_W_SOA = (
    b"\x00\x00\x81\x80\x00\x01\x00\x00\x00\x01\x00\x00\x09\x73\x68\x61"
    b"\x72\x65\x2d\x64\x6e\x73\x03\x63\x6f\x6d\x00\x00\x1c\x00\x01\xc0"
    b"\x0c\x00\x06\x00\x01\x00\x00\x05\xb3\x00\x2f\x04\x74\x72\x6f\x79"
    b"\x02\x6e\x73\x0a\x63\x6c\x6f\x75\x64\x66\x6c\x61\x72\x65\xc0\x16"
    b"\x03\x64\x6e\x73\xc0\x33\x8a\x37\xca\x3f\x00\x00\x27\x10\x00\x00"
    b"\x09\x60\x00\x09\x3a\x80\x00\x00\x07\x08"
)
RESPONSE_W_SOA_CBOR = """
[
    33152,
    ["share-dns", "com"],
    [],
    [
        [
            1459,
            6,
            [
                "troy",
                "ns",
                "cloudflare",
                7(1),
                2318912063,
                10000,
                2400,
                604800,
                1800,
                "dns",
                7(4),
            ],
        ],
    ],
    [],
]
"""
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
RESPONSE_AAAA_CBOR = """
[
    33152,
    ["example", "org"],
    [[22865, h'26062800022000010248189325c81946']],
    [
        [7(1), 111088, 2, "d0", "org", "afilias-nst", 7(1)],
        [7(1), 111088, 2, "b0", 7(3)],
        [7(1), 111088, 2, "b2", 7(3)],
        [7(1), 111088, 2, "c0", "org", "afilias-nst", "info"],
        [7(1), 111088, 2, "a0", 7(8)],
        [7(1), 111088, 2, "a2", 7(8)],
    ],
    [
        [7(11), 111088, 1, h'c7133801'],
        [7(12), 111088, 1, h'c7f97001'],
        [7(5), 111088, 1, h'c7133601'],
        [7(6), 111088, 1, h'c7f97801'],
        [7(7), 111088, 1, h'c7133501'],
        [7(2), 111088, 1, h'c7133901'],
        [7(11), 111088, h'20010500000e00000000000000000001'],
        [7(12), 111088, h'20010500004000000000000000000001'],
        [7(5), 111088, h'20010500000c00000000000000000001'],
        [7(6), 111088, h'20010500004800000000000000000001'],
        [7(7), 111088, h'20010500000b00000000000000000001'],
        [7(2), 111088, h'20010500000f00000000000000000001'],
        141([4096, {10: h'1619c47f6ed6c4abefece879643546d37b9cb7d561aad9c2'}]),
    ],
]
"""
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
        MDNS_QUERY,
        True,
        None,
        False,
        MDNS_QUERY_CBOR,
        id="mDNS query",
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
        RESPONSE_W_SOA,
        False,
        None,
        False,
        RESPONSE_W_SOA_CBOR,
        id="response SOA (w/o original query)",
    ),
    pytest.param(
        RESPONSE_AAAA,
        False,
        QUERY_AAAA_CBOR,
        False,
        """
[
    33152,
    [[22865, h'26062800022000010248189325c81946']],
    [
        ["org", 111088, 2, "d0", "org", "afilias-nst", 7(0)],
        [7(0), 111088, 2, "b0", 7(2)],
        [7(0), 111088, 2, "b2", 7(2)],
        [7(0), 111088, 2, "c0", "org", "afilias-nst", "info"],
        [7(0), 111088, 2, "a0", 7(7)],
        [7(0), 111088, 2, "a2", 7(7)],
    ],
    [
        [7(10), 111088, 1, h'c7133801'],
        [7(11), 111088, 1, h'c7f97001'],
        [7(4), 111088, 1, h'c7133601'],
        [7(5), 111088, 1, h'c7f97801'],
        [7(6), 111088, 1, h'c7133501'],
        [7(1), 111088, 1, h'c7133901'],
        [7(10), 111088, h'20010500000e00000000000000000001'],
        [7(11), 111088, h'20010500004000000000000000000001'],
        [7(4), 111088, h'20010500000c00000000000000000001'],
        [7(5), 111088, h'20010500004800000000000000000001'],
        [7(6), 111088, h'20010500000b00000000000000000001'],
        [7(1), 111088, h'20010500000f00000000000000000001'],
        141([4096, {10: h'1619c47f6ed6c4abefece879643546d37b9cb7d561aad9c2'}]),
    ],
]
        """,
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
        """
[
    [111088, h'2001050000', h'c7', 226(h'13'), "org", "afilias-nst", 226(h'f9')],
    [
        33152,
        ["example", simple(4)],
        [[22865, h'26062800022000010248189325c81946']],
        [
            [7(1), simple(0), 2, "d0", simple(4), simple(5), 7(1)],
            [7(1), simple(0), 2, "b0", 7(3)],
            [7(1), simple(0), 2, "b2", 7(3)],
            [7(1), simple(0), 2, "c0", simple(4), simple(5), "info"],
            [7(1), simple(0), 2, "a0", 7(8)],
            [7(1), simple(0), 2, "a2", 7(8)],
        ],
        [
            [7(11), simple(0), 1, 227(h'3801')],
            [7(12), simple(0), 1, 230(h'7001')],
            [7(5), simple(0), 1, 227(h'3601')],
            [7(6), simple(0), 1, 230(h'7801')],
            [7(7), simple(0), 1, 227(h'3501')],
            [7(2), simple(0), 1, 227(h'3901')],
            [7(11), simple(0), 225(h'0e00000000000000000001')],
            [7(12), simple(0), 225(h'4000000000000000000001')],
            [7(5), simple(0), 225(h'0c00000000000000000001')],
            [7(6), simple(0), 225(h'4800000000000000000001')],
            [7(7), simple(0), 225(h'0b00000000000000000001')],
            [7(2), simple(0), 225(h'0f00000000000000000001')],
            141([4096, {10: h'1619c47f6ed6c4abefece879643546d37b9cb7d561aad9c2'}]),
        ],
    ],
]
        """,
        id="response example.org AAAA (w/o original query), packed",
    ),
    pytest.param(
        RESPONSE_AAAA,
        False,
        QUERY_AAAA_CBOR,
        True,
        """
[
    [111088, h'2001050000', h'c7', 226(h'13'), "org", "afilias-nst", 226(h'f9')],
    [
        33152,
        [[22865, h'26062800022000010248189325c81946']],
        [
            ["org", simple(0), 2, "d0", simple(4), simple(5), 7(0)],
            [7(0), simple(0), 2, "b0", 7(2)],
            [7(0), simple(0), 2, "b2", 7(2)],
            [7(0), simple(0), 2, "c0", simple(4), simple(5), "info"],
            [7(0), simple(0), 2, "a0", 7(7)],
            [7(0), simple(0), 2, "a2", 7(7)],
        ],
        [
            [7(10), simple(0), 1, 227(h'3801')],
            [7(11), simple(0), 1, 230(h'7001')],
            [7(4), simple(0), 1, 227(h'3601')],
            [7(5), simple(0), 1, 230(h'7801')],
            [7(6), simple(0), 1, 227(h'3501')],
            [7(1), simple(0), 1, 227(h'3901')],
            [7(10), simple(0), 225(h'0e00000000000000000001')],
            [7(11), simple(0), 225(h'4000000000000000000001')],
            [7(4), simple(0), 225(h'0c00000000000000000001')],
            [7(5), simple(0), 225(h'4800000000000000000001')],
            [7(6), simple(0), 225(h'0b00000000000000000001')],
            [7(1), simple(0), 225(h'0f00000000000000000001')],
            141([4096, {10: h'1619c47f6ed6c4abefece879643546d37b9cb7d561aad9c2'}]),
        ],
    ],
]
        """,
        id="response example.org AAAA (w/ original query), packed",
    ),
    pytest.param(
        bytes.fromhex("00000100000100000000000007736f6c2d646f630378797a0000300001"),
        True,
        None,
        False,
        '[256, ["sol-doc", "xyz", 48]]',
        id="Query for complicated name structure",
    ),
    pytest.param(
        bytes.fromhex(
            "00008180000100020000000003366e7702696d0000020001c00c000200010000546000180"
            "4656c6c65026e730a636c6f7564666c61726503636f6d00c00c0002000100005460000603"
            "6a696dc029"
        ),
        False,
        '[256, ["sol-doc", "xyz", 48]]',
        True,
        """
[
    [21600],
    [
        33152,
        ["6nw", "im", 2],
        [
          [7(0), simple(0), 2, "elle", "ns", "cloudflare", "com"],
          [7(0), simple(0), 2, "jim", 7(3)],
        ],
    ],
]
        """,
        id="Packed with complicated name structure",
    ),
    pytest.param(
        bytes.fromhex(
            "0000818000010002000000000172047475726e03636f6d0000010001c00c0005000100000"
            "25800170172047475726e03636f6d06616b61646e73036e657400c028000100010000012c"
            "00043274c215"
        ),
        False,
        bytes.fromhex("82190100846172647475726e63636f6d01"),
        False,
        """
[
    33152,
    [[600, 5, "r", "turn", "com", "akadns", "net"], [7(0), 300, 1, h'3274c215']],
]
        """,
        id="Testing comp_ref",
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
            file,
            packed=packed,
            always_omit_question=False,
        )
        if isinstance(orig_query, str):
            # pylint: disable=no-member
            orig_query = cbor_diag.diag2cbor(orig_query)
        encoder.encode(wire, orig_query)
        res = file.getvalue()
        # pylint: disable=no-member
        print(cbor_diag.cbor2diag(res))
        print(len(res), len(wire), len(res) / len(wire))
        if isinstance(exp_cbor, str):
            # pylint: disable=no-member
            exp_cbor = cbor_diag.diag2cbor(exp_cbor)
        assert res == exp_cbor
