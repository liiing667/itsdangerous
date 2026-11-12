"""Tests for the serializer-only :meth:`verify` entry point.

The data serializer used here counts every ``loads`` call and raises
if it is ever asked to deserialize, proving that ``verify`` only checks
signatures and never executes a potentially dangerous serializer such
as :mod:`pickle`.
"""

from __future__ import annotations

import hashlib
import pickle
from functools import partial

import pytest
from freezegun import freeze_time

from itsdangerous import Serializer
from itsdangerous import TimedSerializer
from itsdangerous import URLSafeSerializer
from itsdangerous import URLSafeTimedSerializer
from itsdangerous import VerifyResult
from itsdangerous import VerifyStatus
from itsdangerous.exc import BadPayload
from itsdangerous.signer import Signer


class DangerousSerializer:
    """Stand-in for an exploitable serializer such as :mod:`pickle`."""

    def __init__(self) -> None:
        self.loads_count = 0
        self.dumps_count = 0

    def dumps(self, obj, /):
        self.dumps_count += 1
        return pickle.dumps(obj)

    def loads(self, payload, /):
        self.loads_count += 1
        raise RuntimeError("dangerous serializer must never be executed")


@pytest.fixture()
def dangerous_serializer():
    return DangerousSerializer()


@pytest.fixture(params=(Serializer, URLSafeSerializer))
def serializer_factory(request, dangerous_serializer):
    return partial(
        request.param, secret_key="secret-key", serializer=dangerous_serializer
    )


@pytest.fixture()
def serializer(serializer_factory):
    return serializer_factory()


@pytest.fixture(params=(TimedSerializer, URLSafeTimedSerializer))
def timed_serializer_factory(request, dangerous_serializer):
    return partial(
        request.param, secret_key="secret-key", serializer=dangerous_serializer
    )


@pytest.fixture()
def timed_serializer(timed_serializer_factory):
    return timed_serializer_factory()


class TestVerify:
    def test_valid_returns_raw_payload_bytes(self, serializer, dangerous_serializer):
        signed = serializer.dumps({"id": 42})

        result = serializer.verify(signed)

        assert isinstance(result, VerifyResult)
        assert result.valid is True
        assert result.status is VerifyStatus.VALID
        assert result.payload == serializer.dump_payload({"id": 42})
        assert isinstance(result.payload, bytes)
        assert dangerous_serializer.loads_count == 0

    def test_tampered_value_is_bad_signature(self, serializer, dangerous_serializer):
        signed = serializer.dumps({"id": 42})

        result = serializer.verify(signed[:-1])

        assert result.valid is False
        assert result.status is VerifyStatus.BAD_SIGNATURE
        assert result.payload is None
        assert dangerous_serializer.loads_count == 0

    def test_wrong_key_is_bad_signature(self, serializer_factory, dangerous_serializer):
        signed = serializer_factory(secret_key="first-key").dumps({"id": 42})
        other = serializer_factory(secret_key="other-key")

        result = other.verify(signed)

        assert result.status is VerifyStatus.BAD_SIGNATURE
        assert result.payload is None
        assert dangerous_serializer.loads_count == 0

    def test_key_rotation_accepts_old_key(
        self, serializer_factory, dangerous_serializer
    ):
        old = serializer_factory(secret_key=["old-key"])
        signed = old.dumps({"id": 42})
        rotated = serializer_factory(secret_key=["old-key", "new-key"])

        result = rotated.verify(signed)

        assert result.status is VerifyStatus.VALID
        assert result.payload == old.dump_payload({"id": 42})
        assert dangerous_serializer.loads_count == 0

    def test_salt_is_reused(self, serializer, dangerous_serializer):
        signed = serializer.dumps({"id": 42}, salt="other")

        assert serializer.verify(signed).status is VerifyStatus.BAD_SIGNATURE
        result = serializer.verify(signed, salt="other")
        assert result.status is VerifyStatus.VALID
        assert result.payload == serializer.dump_payload({"id": 42})
        assert dangerous_serializer.loads_count == 0

    def test_no_separator_is_bad_signature(self, serializer, dangerous_serializer):
        result = serializer.verify(b"no-separator-here")

        assert result.status is VerifyStatus.BAD_SIGNATURE
        assert result.payload is None
        assert dangerous_serializer.loads_count == 0

    def test_fallback_signers_are_reused(
        self, serializer_factory, dangerous_serializer
    ):
        primary = serializer_factory(signer_kwargs={"digest_method": hashlib.sha256})
        signed = primary.dumps({"id": 42})
        fallback = serializer_factory(
            signer_kwargs={"digest_method": hashlib.sha1},
            fallback_signers=[{"digest_method": hashlib.sha256}],
        )

        result = fallback.verify(signed)

        assert result.status is VerifyStatus.VALID
        assert result.payload == primary.dump_payload({"id": 42})
        assert dangerous_serializer.loads_count == 0

    def test_loads_still_invokes_serializer_and_fails(
        self, serializer, dangerous_serializer
    ):
        signed = serializer.dumps({"id": 42})

        with pytest.raises(BadPayload):
            serializer.loads(signed)

        assert dangerous_serializer.loads_count == 1
        assert serializer.verify(signed).status is VerifyStatus.VALID


class TestTimedVerify:
    def test_valid_returns_raw_payload_bytes(
        self, timed_serializer, dangerous_serializer
    ):
        with freeze_time("2020-01-01"):
            signed = timed_serializer.dumps({"id": 42})

        result = timed_serializer.verify(signed)

        assert result.status is VerifyStatus.VALID
        assert result.payload == timed_serializer.dump_payload({"id": 42})
        assert isinstance(result.payload, bytes)
        assert dangerous_serializer.loads_count == 0

    def test_expired_is_reported_without_serializer(
        self, timed_serializer, dangerous_serializer
    ):
        with freeze_time("2020-01-01"):
            signed = timed_serializer.dumps({"id": 42})

        with freeze_time("2020-01-02"):
            result = timed_serializer.verify(signed, max_age=60)

        assert result.valid is False
        assert result.status is VerifyStatus.EXPIRED
        assert result.payload is None
        assert dangerous_serializer.loads_count == 0

    def test_within_max_age_is_valid(self, timed_serializer, dangerous_serializer):
        with freeze_time("2020-01-01") as frozen_time:
            signed = timed_serializer.dumps({"id": 42})
            frozen_time.tick(10)
            result = timed_serializer.verify(signed, max_age=60)

        assert result.status is VerifyStatus.VALID
        assert result.payload == timed_serializer.dump_payload({"id": 42})
        assert dangerous_serializer.loads_count == 0

    def test_wrong_key_is_bad_time_signature(
        self, timed_serializer_factory, dangerous_serializer
    ):
        with freeze_time("2020-01-01"):
            signed = timed_serializer_factory(secret_key="first-key").dumps({"id": 42})

        other = timed_serializer_factory(secret_key="other-key")
        result = other.verify(signed, max_age=60)

        # TimestampSigner wraps a failed signature check in
        # BadTimeSignature, mirroring the exception raised by loads.
        assert result.status is VerifyStatus.BAD_TIME_SIGNATURE
        assert result.payload is None
        assert dangerous_serializer.loads_count == 0

    def test_tampered_value_does_not_expire_first(
        self, timed_serializer, dangerous_serializer
    ):
        with freeze_time("2020-01-01"):
            signed = timed_serializer.dumps({"id": 42})

        with freeze_time("2020-01-02"):
            result = timed_serializer.verify(signed[:-1], max_age=60)

        assert result.status is VerifyStatus.BAD_TIME_SIGNATURE
        assert result.payload is None
        assert dangerous_serializer.loads_count == 0

    def test_missing_timestamp_is_bad_time_signature(
        self, timed_serializer, dangerous_serializer
    ):
        signed = Signer(timed_serializer.secret_keys, salt=timed_serializer.salt).sign(
            b"raw-payload"
        )

        result = timed_serializer.verify(signed)

        assert result.status is VerifyStatus.BAD_TIME_SIGNATURE
        assert result.payload is None
        assert dangerous_serializer.loads_count == 0

    def test_salt_is_reused(self, timed_serializer, dangerous_serializer):
        signed = timed_serializer.dumps({"id": 42}, salt="other")

        assert (
            timed_serializer.verify(signed, max_age=60).status
            is VerifyStatus.BAD_TIME_SIGNATURE
        )
        result = timed_serializer.verify(signed, max_age=60, salt="other")
        assert result.status is VerifyStatus.VALID
        assert dangerous_serializer.loads_count == 0
