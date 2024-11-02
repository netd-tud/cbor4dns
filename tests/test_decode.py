# pylint: disable=missing-function-docstring,missing-module-docstring


import io

import cbor_diag
import pytest

import cbor4dns.decode

from .test_encode import TEST_VECTOR


@pytest.mark.parametrize("exp_res, is_query, orig_query, packed, cbor", TEST_VECTOR)
def test_decoder_decode(exp_res, is_query, orig_query, packed, cbor):
    if isinstance(orig_query, str):
        # pylint: disable=no-member
        orig_query = cbor_diag.diag2cbor(orig_query)
    if isinstance(cbor, str):
        # pylint: disable=no-member
        cbor = cbor_diag.diag2cbor(cbor)
    with io.BytesIO(cbor) as file:
        decoder = cbor4dns.decode.Decoder(file)
        res = decoder.decode(
            (
                cbor4dns.decode.MsgType.QUERY
                if is_query
                else cbor4dns.decode.MsgType.RESPONSE
            ),
            orig_query=orig_query,
            packed=packed,
        )
        assert res.to_wire(want_shuffle=False) == exp_res
