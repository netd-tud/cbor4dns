import io
import pprint

import cbor2
import pytest

import cbor2_dns.encode

TEST_VECTOR = (
    pytest.param(
        b"\xd5\xcd\x01\x20\x00\x01\x00\x00\x00\x00\x00\x01\x07\x65\x78\x61"
        b"\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x00\x1c\x00\x01\x00\x00\x29"
        b"\x04\xd0\x00\x00\x00\x00\x00\x0c\x00\x0a\x00\x08\x99\x21\x09\x65"
        b"\x33\xa3\x66\xb5",
        None,
        b"\x84\x19\xd5\xcd\x19\x01 \x81kexample.org\x81W\x00\x00)\x04\xd0\x00"
        b"\x00\x00\x00\x00\x0c\x00\n\x00\x08\x99!\te3\xa3f\xb5",
        id="query example.org AAAA"
    ),
    pytest.param(
        b"\x70\x75\x01\x20\x00\x01\x00\x00\x00\x00\x00\x01\x07\x65\x78\x61"
        b"\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x00\x01\x00\x01\x00\x00\x29"
        b"\x04\xd0\x00\x00\x00\x00\x00\x0c\x00\x0a\x00\x08\x74\x5e\x6c\x10"
        b"\xa8\x46\x19\xa4",
        None,
        b"\x84\x19pu\x19\x01 \x82kexample.org\x01\x81W\x00\x00)\x04\xd0"
        b"\x00\x00\x00\x00\x00\x0c\x00\n\x00\x08t^l\x10\xa8F\x19\xa4",
        id="query example.org A"
    ),
    pytest.param(
        b"\xb5\x3e\x81\x80\x00\x01\x00\x01\x00\x06\x00\x0d\x07\x65\x78\x61"
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
        b"\xd9\xc2",
        None,
        b"\x86\x19\xb5>\x19\x81\x80\x81kexample.org\x81\x82\x19YQP&\x06(\x00\x02 "
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
        b"\xef\xec\xe8yd5F\xd3{\x9c\xb7\xd5a\xaa\xd9\xc2",
        id="response example.org AAAA (w/o original query)"
    ),
    pytest.param(
        b"\xb5\x3e\x81\x80\x00\x01\x00\x01\x00\x06\x00\x0d\x07\x65\x78\x61"
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
        b"\xd9\xc2",
        b"\x84\x19\xd5\xcd\x19\x01 \x81kexample.org\x81W\x00\x00)\x04\xd0\x00"
        b"\x00\x00\x00\x00\x0c\x00\n\x00\x08\x99!\te3\xa3f\xb5",
        b"\x85\x19\xb5>\x19\x81\x80\x81\x82\x19YQP&\x06(\x00\x02 \x00\x01\x02H\x18"
        b"\x93%\xc8\x19F\x86\x84corg\x1a\x00\x01\xb1\xf0\x02vd0.org.afilias-nst.org"
        b"\x84corg\x1a\x00\x01\xb1\xf0\x02vb0.org.afilias-nst.org\x84corg\x1a"
        b"\x00\x01\xb1\xf0\x02vb2.org.afilias-nst.org\x84corg\x1a\x00\x01\xb1\xf0\x02w"
        b"c0.org.afilias-nst.info\x84corg\x1a\x00\x01\xb1\xf0\x02wa0.org.afilias-ns"
        b"t.info\x84corg\x1a\x00\x01\xb1\xf0\x02wa2.org.afilias-nst.info\x8d\x84wa0.o"
        b"rg.afilias-nst.info\x1a\x00\x01\xb1\xf0\x01D\xc7\x138\x01\x84wa2.org.afili"
        b"as-nst.info\x1a\x00\x01\xb1\xf0\x01D\xc7\xf9p\x01\x84vb0.org.afilias-nst.o"
        b"rg\x1a\x00\x01\xb1\xf0\x01D\xc7\x136\x01\x84vb2.org.afilias-nst.or"
        b"g\x1a\x00\x01\xb1\xf0\x01D\xc7\xf9x\x01\x84wc0.org.afilias-nst.inf"
        b"o\x1a\x00\x01\xb1\xf0\x01D\xc7\x135\x01\x84vd0.org.afilias-nst.org"
        b"\x1a\x00\x01\xb1\xf0\x01D\xc7\x139\x01\x83wa0.org.afilias-nst.info"
        b"\x1a\x00\x01\xb1\xf0P \x01\x05\x00\x00\x0e\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x01\x83wa2.org.afilias-nst.info\x1a\x00\x01\xb1\xf0P \x01\x05"
        b"\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x83vb0.org.afilias-nst.or"
        b"g\x1a\x00\x01\xb1\xf0P \x01\x05\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x01\x83vb2.org.afilias-nst.org\x1a\x00\x01\xb1\xf0P \x01\x05"
        b"\x00\x00H\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x83wc0.org.afilias-nst.in"
        b"fo\x1a\x00\x01\xb1\xf0P \x01\x05\x00\x00\x0b\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x01\x83vd0.org.afilias-nst.org\x1a\x00\x01\xb1\xf0P \x01"
        b"\x05\x00\x00\x0f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01X'\x00\x00)\x10"
        b"\x00\x00\x00\x00\x00\x00\x1c\x00\n\x00\x18\x16\x19\xc4\x7fn\xd6\xc4\xab\xef"
        b"\xec\xe8yd5F\xd3{\x9c\xb7\xd5a\xaa\xd9\xc2",
        id="response example.org AAAA (w/ original query)"
    ),
)


@pytest.mark.parametrize("wire, orig_query, exp_cbor", TEST_VECTOR)
def test_encoder_encode(wire, orig_query, exp_cbor):
    with io.BytesIO() as fp:
        encoder = cbor2_dns.encode.Encoder(fp)
        encoder.encode(wire, orig_query)
        res = fp.getvalue()
        pprint.pprint(cbor2.loads(res))
        assert res == exp_cbor
