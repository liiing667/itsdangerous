from datetime import datetime
from datetime import timedelta
from datetime import timezone
from functools import partial

import pytest
from freezegun import freeze_time

from itsdangerous.exc import BadTimeSignature
from itsdangerous.exc import SignatureExpired
from itsdangerous.signer import Signer
from itsdangerous.timed import TimedSerializer
from itsdangerous.timed import TimestampSigner
from test_itsdangerous.test_serializer import TestSerializer
from test_itsdangerous.test_signer import TestSigner


class FreezeMixin:
    @pytest.fixture()
    def ts(self):
        return datetime(2011, 6, 24, 0, 9, 5, tzinfo=timezone.utc)

    @pytest.fixture(autouse=True)
    def freeze(self, ts):
        with freeze_time(ts) as ft:
            yield ft


class TestTimestampSigner(FreezeMixin, TestSigner):
    @pytest.fixture()
    def signer_factory(self):
        return partial(TimestampSigner, secret_key="secret-key")

    def test_max_age(self, signer, ts, freeze):
        signed = signer.sign("value")
        freeze.tick()
        assert signer.unsign(signed, max_age=10) == b"value"
        freeze.tick(timedelta(seconds=10))

        with pytest.raises(SignatureExpired) as exc_info:
            signer.unsign(signed, max_age=10)

        assert exc_info.value.date_signed == ts

    def test_return_timestamp(self, signer, ts):
        signed = signer.sign("value")
        assert signer.unsign(signed, return_timestamp=True) == (b"value", ts)

    def test_timestamp_missing(self, signer):
        other = Signer("secret-key")
        signed = other.sign("value")

        with pytest.raises(BadTimeSignature) as exc_info:
            signer.unsign(signed)

        assert "missing" in str(exc_info.value)
        assert exc_info.value.date_signed is None

    def test_malformed_timestamp(self, signer):
        other = Signer("secret-key")
        signed = other.sign(b"value.____________")

        with pytest.raises(BadTimeSignature) as exc_info:
            signer.unsign(signed)

        assert "Malformed" in str(exc_info.value)
        assert exc_info.value.date_signed is None

    def test_malformed_future_timestamp(self, signer):
        signed = b"value.TgPVoaGhoQ.AGBfQ6G6cr07byTRt0zAdPljHOY"

        with pytest.raises(BadTimeSignature) as exc_info:
            signer.unsign(signed)

        assert "Malformed" in str(exc_info.value)
        assert exc_info.value.date_signed is None

    def test_future_age(self, signer):
        signed = signer.sign("value")

        with freeze_time("1971-05-31"):
            with pytest.raises(SignatureExpired) as exc_info:
                signer.unsign(signed, max_age=10)

        assert isinstance(exc_info.value.date_signed, datetime)

    def test_sig_error_date_signed(self, signer):
        signed = signer.sign("my string").replace(b"my", b"other", 1)

        with pytest.raises(BadTimeSignature) as exc_info:
            signer.unsign(signed)

        assert isinstance(exc_info.value.date_signed, datetime)


class TestTimedSerializer(FreezeMixin, TestSerializer):
    @pytest.fixture()
    def serializer_factory(self):
        return partial(TimedSerializer, secret_key="secret_key")

    def test_max_age(self, serializer, value, ts, freeze):
        signed = serializer.dumps(value)
        freeze.tick()
        assert serializer.loads(signed, max_age=10) == value
        freeze.tick(timedelta(seconds=10))

        with pytest.raises(SignatureExpired) as exc_info:
            serializer.loads(signed, max_age=10)

        assert exc_info.value.date_signed == ts
        assert serializer.load_payload(exc_info.value.payload) == value

    def test_return_payload(self, serializer, value, ts):
        signed = serializer.dumps(value)
        assert serializer.loads(signed, return_timestamp=True) == (value, ts)


class TestTimestampSignerKeyIds(FreezeMixin):
    @pytest.fixture()
    def signer(self):
        return TimestampSigner(["old-key", "new-key"], key_ids=["1", "2"])

    def test_sign_includes_key_id(self, signer):
        signed = signer.sign("value")
        assert signed.rsplit(b".", 2)[1] == b"2"
        assert signer.unsign(signed) == b"value"

    def test_max_age(self, signer, ts, freeze):
        signed = signer.sign("value")
        freeze.tick()
        assert signer.unsign(signed, max_age=10) == b"value"
        freeze.tick(timedelta(seconds=10))

        with pytest.raises(SignatureExpired):
            signer.unsign(signed, max_age=10)

    def test_legacy_value_fallback(self, signer, ts):
        legacy = TimestampSigner("new-key")
        signed = legacy.sign("value")
        assert signer.unsign(signed, return_timestamp=True) == (b"value", ts)

    def test_bad_signature_payload(self, signer):
        signed = signer.sign("my string").replace(b"my", b"other", 1)

        with pytest.raises(BadTimeSignature) as exc_info:
            signer.unsign(signed)

        assert exc_info.value.payload == b"other string"

    def test_migrate(self, signer, ts):
        legacy = TimestampSigner("old-key")
        old_signed = legacy.sign("value")
        new_signed = signer.migrate(old_signed)
        assert new_signed.rsplit(b".", 2)[1] == b"2"
        assert signer.unsign(new_signed, return_timestamp=True) == (b"value", ts)


class TestTimedSerializerKeyIds(FreezeMixin):
    @pytest.fixture()
    def serializer(self):
        return TimedSerializer(
            ["old-key", "new-key"], signer_kwargs={"key_ids": ["1", "2"]}
        )

    def test_dumps_includes_key_id(self, serializer, ts):
        signed = serializer.dumps({"id": 42})
        assert signed.rsplit(".", 2)[1] == "2"
        assert serializer.loads(signed, return_timestamp=True) == ({"id": 42}, ts)

    def test_migrate(self, serializer, ts, freeze):
        legacy = TimedSerializer("old-key")
        old_signed = legacy.dumps({"id": 42})
        freeze.tick()
        new_signed = serializer.migrate(old_signed, max_age=10)
        assert new_signed.rsplit(".", 2)[1] == "2"
        # Migrating re-signs with the current timestamp.
        assert serializer.loads(new_signed, return_timestamp=True) == (
            {"id": 42},
            ts + timedelta(seconds=1),
        )
