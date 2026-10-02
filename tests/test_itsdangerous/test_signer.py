import hashlib
from functools import partial

import pytest

from itsdangerous.exc import BadSignature
from itsdangerous.signer import HMACAlgorithm
from itsdangerous.signer import NoneAlgorithm
from itsdangerous.signer import Signer
from itsdangerous.signer import SigningAlgorithm


class _ReverseAlgorithm(SigningAlgorithm):
    def get_signature(self, key, value):
        return (key + value)[::-1]


class TestSigner:
    @pytest.fixture()
    def signer_factory(self):
        return partial(Signer, secret_key="secret-key")

    @pytest.fixture()
    def signer(self, signer_factory):
        return signer_factory()

    def test_signer(self, signer):
        signed = signer.sign("my string")
        assert isinstance(signed, bytes)
        assert signer.validate(signed)
        out = signer.unsign(signed)
        assert out == b"my string"

    def test_no_separator(self, signer):
        signed = signer.sign("my string")
        signed = signed.replace(signer.sep, b"*", 1)
        assert not signer.validate(signed)

        with pytest.raises(BadSignature):
            signer.unsign(signed)

    def test_broken_signature(self, signer):
        signed = signer.sign("b")
        bad_signed = signed[:-1]
        bad_sig = bad_signed.rsplit(b".", 1)[1]
        assert not signer.verify_signature(b"b", bad_sig)

        with pytest.raises(BadSignature) as exc_info:
            signer.unsign(bad_signed)

        assert exc_info.value.payload == b"b"

    def test_changed_value(self, signer):
        signed = signer.sign("my string")
        signed = signed.replace(b"my", b"other", 1)
        assert not signer.validate(signed)

        with pytest.raises(BadSignature):
            signer.unsign(signed)

    def test_invalid_separator(self, signer_factory):
        with pytest.raises(ValueError) as exc_info:
            signer_factory(sep="-")

        assert "separator cannot be used" in str(exc_info.value)

    @pytest.mark.parametrize(
        "key_derivation", ("concat", "django-concat", "hmac", "none")
    )
    def test_key_derivation(self, signer_factory, key_derivation):
        signer = signer_factory(key_derivation=key_derivation)
        assert signer.unsign(signer.sign("value")) == b"value"

    def test_invalid_key_derivation(self, signer_factory):
        signer = signer_factory(key_derivation="invalid")

        with pytest.raises(TypeError):
            signer.derive_key()

    def test_digest_method(self, signer_factory):
        signer = signer_factory(digest_method=hashlib.md5)
        assert signer.unsign(signer.sign("value")) == b"value"

    @pytest.mark.parametrize(
        "algorithm", (None, NoneAlgorithm(), HMACAlgorithm(), _ReverseAlgorithm())
    )
    def test_algorithm(self, signer_factory, algorithm):
        signer = signer_factory(algorithm=algorithm)
        assert signer.unsign(signer.sign("value")) == b"value"

        if algorithm is None:
            assert signer.algorithm.digest_method == signer.digest_method

    def test_secret_keys(self):
        signer = Signer("a")
        signed = signer.sign("my string")
        assert isinstance(signed, bytes)

        signer = Signer(["a", "b"])
        assert signer.validate(signed)
        out = signer.unsign(signed)
        assert out == b"my string"


def test_abstract_algorithm():
    alg = SigningAlgorithm()

    with pytest.raises(NotImplementedError):
        alg.get_signature(b"a", b"b")


class TestKeyIds:
    @pytest.fixture()
    def signer(self):
        return Signer(["old-key", "new-key"], key_ids=["1", "2"])

    def test_sign_includes_key_id(self, signer):
        signed = signer.sign("my string")
        assert signed.rsplit(b".", 2)[1] == b"2"
        assert signer.unsign(signed) == b"my string"
        assert signer.validate(signed)

    def test_no_key_ids_unchanged(self):
        signer = Signer(["old-key", "new-key"])
        signed = signer.sign("my string")
        assert signed == b"my string." + signed.rsplit(b".", 1)[1]
        assert signer.unsign(signed) == b"my string"

    def test_legacy_value_fallback(self, signer):
        legacy = Signer(["old-key", "new-key"])
        signed = legacy.sign("my string")
        assert signer.unsign(signed) == b"my string"
        assert signer.validate(signed)

    def test_legacy_value_signed_with_old_key(self, signer):
        legacy = Signer("old-key")
        signed = legacy.sign("my string")
        assert signer.unsign(signed) == b"my string"

    def test_legacy_value_ending_with_key_id(self, signer):
        # A legacy value that coincidentally ends with the separator
        # and a valid key id must still unsign to the full value.
        legacy = Signer("old-key")
        signed = legacy.sign("value.1")
        assert signer.unsign(signed) == b"value.1"

    def test_wrong_key_id(self, signer):
        signed = signer.sign("my string")
        changed = signed.replace(b".2.", b".1.")
        assert not signer.validate(changed)

        with pytest.raises(BadSignature) as exc_info:
            signer.unsign(changed)

        assert exc_info.value.payload == b"my string"

    def test_unknown_key_id(self, signer):
        signed = signer.sign("my string")
        changed = signed.replace(b".2.", b".3.")
        assert not signer.validate(changed)

        with pytest.raises(BadSignature):
            signer.unsign(changed)

    def test_fast_path_selects_matching_key(self):
        # The newest key signs, and unsigning selects it by id even
        # though the oldest key is tried first in the legacy path.
        signer = Signer(["a", "b"], key_ids=["ka", "kb"])
        signed = signer.sign("value")
        assert signer.unsign(signed) == b"value"

        other = Signer(["b", "a"], key_ids=["kb", "ka"])
        assert other.unsign(signed) == b"value"

    def test_migrate(self, signer):
        legacy = Signer("old-key")
        old_signed = legacy.sign("my string")
        new_signed = signer.migrate(old_signed)
        assert new_signed.rsplit(b".", 2)[1] == b"2"
        assert signer.unsign(new_signed) == b"my string"

    def test_migrate_already_migrated(self, signer):
        signed = signer.sign("my string")
        assert signer.unsign(signer.migrate(signed)) == b"my string"

    def test_migrate_invalid(self, signer):
        with pytest.raises(BadSignature):
            signer.migrate(b"value.bad-sig")

    @pytest.mark.parametrize(
        "key_ids",
        (
            ["1"],
            ["1", "1"],
            ["1", ""],
            ["1", "2.0"],
        ),
        ids=("length", "duplicate", "empty", "contains-sep"),
    )
    def test_invalid_key_ids(self, key_ids):
        with pytest.raises(ValueError):
            Signer(["old-key", "new-key"], key_ids=key_ids)
