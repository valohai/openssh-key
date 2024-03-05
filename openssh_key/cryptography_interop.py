import io

from cryptography.hazmat.backends.openssl.backend import Backend
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateNumbers,
    RSAPublicNumbers,
    rsa_crt_dmp1,
    rsa_crt_dmq1,
    rsa_crt_iqmp,
)

from openssh_key.openssh_io import convert_openssl_unsigned_bn_binary_to_int
from openssh_key.private_keys import _read_KEY_ED25519, _read_KEY_RSA


def _convert_rsa_private_key(keypair):
    backend = Backend()

    # OpenSSH calls `sshbuf_put_bignum2`, which internally calls OpenSSL's
    # `BN_bn2bin` to format an OpenSSL BIGNUM into a binary string.
    # `sshbuf_put_string` is then called to write the binary string (prefixed
    # by a length which `read_openssh_string` skips) to the buffer.

    (n, e, d, iqmp, p, q) = (
        convert_openssl_unsigned_bn_binary_to_int(value) for value in _read_KEY_RSA(io.BytesIO(keypair.private_key))
    )

    numbers = RSAPrivateNumbers(
        d=d,
        p=p,
        q=q,
        dmp1=rsa_crt_dmp1(d, p),
        dmq1=rsa_crt_dmq1(d, q),
        iqmp=rsa_crt_iqmp(p, q),
        public_numbers=RSAPublicNumbers(e=e, n=n),
    )

    return numbers.private_key(backend)


def _convert_ed25519(keypair):
    from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: PLC0415

    (pk, sk) = _read_KEY_ED25519(io.BytesIO(keypair.private_key))
    return ed25519.Ed25519PrivateKey.from_private_bytes(pk)
