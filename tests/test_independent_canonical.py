"""Frozen raw inputs: exact bytes or a refusal, never silent type coercion."""

import base64
import hashlib
import json
from pathlib import Path

import pytest
from actenon.core.json import loads_no_duplicate_keys
from actenon.proof.canonical import canonicalize_bytes as kernel_bytes
from actenon_protocol.canonicalisation import canonicalize_bytes, parse_strict

CORPUS = json.loads((Path(__file__).parent / "fixtures/independent/canonical.json").read_text())


@pytest.mark.parametrize("case", CORPUS["cases"], ids=lambda c: c["id"])
@pytest.mark.parametrize(
    "parser,encoder",
    [(parse_strict, canonicalize_bytes), (loads_no_duplicate_keys, kernel_bytes)],
    ids=["protocol", "kernel"],
)
def test_frozen_raw_corpus(case, parser, encoder):
    raw = base64.b64decode(case["raw_base64"])
    assert hashlib.sha256(raw).hexdigest() == case["raw_sha256"]
    try:
        output = encoder(parser(raw.decode("utf-8")))
    except (ValueError, TypeError, UnicodeError):
        assert case["expected_decision"] == "REFUSE"
    else:
        assert case["expected_decision"] == "ACCEPT"
        assert output.decode() == case["canonical_utf8"]
        assert hashlib.sha256(output).hexdigest() == case["canonical_sha256"]
