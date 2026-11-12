.. module:: itsdangerous.serializer

Serialization Interface
=======================

The :doc:`/signer` only signs bytes. To sign other types, the
:class:`Serializer` class provides a ``dumps``/``loads`` interface
similar to Python's :mod:`json` module, which serializes the object to a
string then signs that.

Use :meth:`~Serializer.dumps` to serialize and sign the data:

.. code-block:: python

    from itsdangerous.serializer import Serializer
    s = Serializer("secret-key")
    s.dumps([1, 2, 3, 4])
    b'[1, 2, 3, 4].r7R9RhGgDPvvWl3iNzLuIIfELmo'

Use :meth:`~Serializer.loads` to verify the signature and deserialize
the data.

.. code-block:: python

    s.loads('[1, 2, 3, 4].r7R9RhGgDPvvWl3iNzLuIIfELmo')
    [1, 2, 3, 4]

By default, data is serialized to JSON with the built-in :mod:`json`
module. This internal serializer can be changed by subclassing.

To record and validate the age of the signature, see :doc:`/timed`.
To serialize to a format that is safe to use in URLs, see
:doc:`/url_safe`.


Responding to Failure
---------------------

Exceptions have helpful attributes which allow you to inspect the
payload if the signature check failed. This has to be done with extra
care because at that point you know that someone tampered with your data
but it might be useful for debugging purposes.

.. code-block:: python

    from itsdangerous.serializer import Serializer
    from itsdangerous.exc import BadSignature, BadData

    s = URLSafeSerializer("secret-key")
    decoded_payload = None

    try:
        decoded_payload = s.loads(data)
        # This payload is decoded and safe
    except BadSignature as e:
        if e.payload is not None:
            try:
                decoded_payload = s.load_payload(e.payload)
            except BadData:
                pass
            # This payload is decoded but unsafe because someone
            # tampered with the signature. The decode (load_payload)
            # step is explicit because it might be unsafe to unserialize
            # the payload (think pickle instead of json!)

If you don't want to inspect attributes to figure out what exactly went
wrong you can also use :meth:`~Serializer.loads_unsafe`:

.. code-block:: python

    sig_okay, payload = s.loads_unsafe(data)

The first item in the returned tuple is a boolean that indicates if the
signature was correct.

Verifying Without Deserializing
-------------------------------

Both :meth:`~Serializer.loads` and :meth:`~Serializer.loads_unsafe`
call the configured data serializer. If that serializer can execute
code while loading, such as :mod:`pickle`, an untrusted payload is
dangerous even for inspection.

Use :meth:`~Serializer.verify` to check the signature only. It reuses
the same secret keys, salt, and fallback signers as
:meth:`~Serializer.loads`, never invokes the data serializer, and
returns a :class:`~itsdangerous.serializer.VerifyResult` with an
explicit :class:`~itsdangerous.serializer.VerifyStatus` and the raw
payload bytes:

.. code-block:: python

    from itsdangerous import VerifyStatus

    result = s.verify(data)

    if result.status is VerifyStatus.VALID:
        # result.payload is the raw, unsigned payload bytes.
        raw_payload = result.payload
    else:
        # The signature was not valid; result.payload is None.
        ...

:meth:`~itsdangerous.timed.TimedSerializer.verify` accepts the same
``max_age`` argument as :meth:`~itsdangerous.timed.TimedSerializer.loads`
and reports an expired signature with
:attr:`~itsdangerous.serializer.VerifyStatus.EXPIRED`. It never raises.


Fallback Signers
----------------

You may want to upgrade the signing parameters without invalidating
existing signatures immediately. For example, you may decide that you
want to use a different digest method. New signatures should use the new
method, but old signatures should still validate.

A list of ``fallback_signers`` can be given that will be tried if
unsigning with the current signer fails. Each item in the list can be:

-   A dict of ``signer_kwargs`` to instantiate the ``signer`` class
    passed to the serializer.
-   A :class:`~itsdangerous.signer.Signer` class to instantiated with
    the ``secret_key``, ``salt``, and ``signer_kwargs`` passed to the
    serializer.
-   A tuple of ``(signer_class, signer_kwargs)`` to instantiate the
    given class with the given args.

For example, this is a serializer that signs using SHA-512, but will
unsign using either SHA-512 or SHA-1:

.. code-block:: python

    s = Serializer(
        signer_kwargs={"digest_method": hashlib.sha512},
        fallback_signers=[{"digest_method": hashlib.sha1}]
    )



API
---

.. autoclass:: Serializer
    :members:
