from functools import partial

import pytest

from itsdangerous.url_safe import URLSafeSerializer
from itsdangerous.url_safe import URLSafeTimedSerializer
from test_itsdangerous.test_serializer import TestSerializer
from test_itsdangerous.test_timed import TestTimedSerializer


class TestURLSafeSerializer(TestSerializer):
    @pytest.fixture()
    def serializer_factory(self):
        return partial(URLSafeSerializer, secret_key="secret-key")

    @pytest.fixture(params=({"id": 42}, pytest.param("a" * 1000, id="zlib")))
    def value(self, request):
        return request.param


class TestURLSafeTimedSerializer(TestURLSafeSerializer, TestTimedSerializer):
    @pytest.fixture()
    def serializer_factory(self):
        return partial(URLSafeTimedSerializer, secret_key="secret-key")


@pytest.mark.parametrize("cls", (URLSafeSerializer, URLSafeTimedSerializer))
def test_key_ids_passthrough(cls):
    serializer = cls(["old-key", "new-key"], signer_kwargs={"key_ids": ["1", "2"]})
    signed = serializer.dumps({"id": 42})
    assert signed.rsplit(".", 2)[1] == "2"
    assert serializer.loads(signed) == {"id": 42}

    legacy = cls(["old-key", "new-key"])
    assert serializer.loads(legacy.dumps({"id": 42})) == {"id": 42}

    migrated = serializer.migrate(legacy.dumps({"id": 42}))
    assert migrated.rsplit(".", 2)[1] == "2"
    assert serializer.loads(migrated) == {"id": 42}
