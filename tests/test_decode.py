# pylint: disable=unknown-option-value
# pylint: disable=missing-function-docstring,missing-module-docstring
# pylint: disable=too-many-arguments,too-many-positional-arguments


import io

import cbor2
import cbor_diag
import pytest

import cbor4dns.decode

from .test_encode import TEST_VECTOR


@pytest.mark.parametrize(
    "cbor, exp",
    [
        (cbor2.CBORSimpleValue(5), True),
        (cbor2.CBORSimpleValue(23), False),
        (cbor2.CBORTag(6, "foo"), True),
        (cbor2.CBORTag(23, "bar"), False),
    ],
)
def test_decoder_is_ref(cbor, exp):
    assert exp == cbor4dns.decode.Decoder.is_ref(cbor)


@pytest.mark.parametrize(
    "exp_res, is_query, orig_query, exp_enforce_question, packed, cbor", TEST_VECTOR
)
def test_decoder_decode(
    exp_res, is_query, orig_query, exp_enforce_question, packed, cbor
):
    if isinstance(orig_query, str):
        # pylint: disable=no-member
        orig_query = cbor_diag.diag2cbor(orig_query)
    if isinstance(cbor, str):
        # pylint: disable=no-member
        cbor = cbor_diag.diag2cbor(cbor)
    with io.BytesIO(cbor) as file:
        decoder = cbor4dns.decode.Decoder(file)
        res, enforce_question = decoder.decode(
            (
                cbor4dns.decode.MsgType.QUERY
                if is_query
                else cbor4dns.decode.MsgType.RESPONSE
            ),
            orig_query=orig_query,
            packed=packed,
        )
        assert res.to_wire(want_shuffle=False) == exp_res
        assert enforce_question == exp_enforce_question
