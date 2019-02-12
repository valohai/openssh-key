import io

from cryptography.hazmat.backends.openssl.backend import Backend
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateNumbers,
    RSAPublicNumbers,
    rsa_crt_dmp1,
    rsa_crt_dmq1,
    rsa_crt_iqmp,
)

from openssh_key.private_keys import _read_KEY_RSA


def _convert_rsa_private_key(keypair):
    backend = Backend()

    def _trim_bn_to_int(s):
        binary = s.lstrip(b'\x00')
        bn_ptr = backend._lib.BN_bin2bn(binary, len(binary), backend._ffi.NULL)
        try:
            return backend._bn_to_int(bn_ptr)
        finally:
            backend._lib.OPENSSL_free(bn_ptr)

    (n, e, d, iqmp, p, q) = [
        _trim_bn_to_int(value)
        for value in _read_KEY_RSA(io.BytesIO(keypair.private_key))
    ]

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
