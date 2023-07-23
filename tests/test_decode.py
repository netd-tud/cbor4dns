# pylint: disable=missing-function-docstring,missing-module-docstring


import io

import dns.message

import cbor4dns.decode

from .test_encode import QUERY_AAAA, QUERY_AAAA_CBOR


def test_decoder_decode():
    cbor = QUERY_AAAA_CBOR
    exp_res = dns.message.from_wire(QUERY_AAAA)
    is_query = False
    with io.BytesIO(cbor) as file:
        decoder = cbor4dns.decode.Decoder(file)
        res = decoder.decode(
            cbor4dns.decode.MsgType.QUERY if is_query else cbor4dns.decode.MsgType.QUERY
        )
        assert res.id == exp_res.id
        assert res.flags == exp_res.flags
        print(res.to_text())
        print(exp_res.to_text())
        assert res == exp_res
