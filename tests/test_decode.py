# pylint: disable=missing-function-docstring,missing-module-docstring


import io

import pytest

import cbor4dns.decode

from .test_encode import TEST_VECTOR


@pytest.mark.parametrize("exp_res, is_query, _, packed, cbor", TEST_VECTOR)
def test_decoder_decode(exp_res, is_query, _, packed, cbor):
    if packed:
        return  # not implemented yet
    with io.BytesIO(cbor) as file:
        decoder = cbor4dns.decode.Decoder(file)
        res = decoder.decode(
            cbor4dns.decode.MsgType.QUERY
            if is_query
            else cbor4dns.decode.MsgType.RESPONSE
        )
        assert res.to_wire(want_shuffle=False) == exp_res
