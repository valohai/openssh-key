import base64
import io
import struct


def convert_openssl_unsigned_bn_binary_to_int(value: bytes) -> int:
    # See `BN_bn2bin`/`BN_bin2bn` in OpenSSL.
    # It turns out that what `BN_bn2bin` produces, in old-school C, is for
    # unsigned big-endian integers (which is the default for `BN_bin2bn`)
    # exactly what Python's `int.from_bytes` expects.
    return int.from_bytes(value.lstrip(b"\x00"), "big")


def read_openssh_string(bin_fp):
    """
    Read a length-prefixed ("OpenSSH-style Pascal") string from a file.

    This format is described in https://tools.ietf.org/html/rfc4251
    (look for "Arbitrary length binary string").

    :param bin_fp: Binary file-like object
    :return: bytes
    """
    len_buf = bin_fp.read(4)
    if not len_buf:
        raise EOFError()
    (length,) = struct.unpack("!I", len_buf)
    buf = bin_fp.read(length)
    if len(buf) != length:
        raise ValueError(
            f"short read for string (expected {int(length)} bytes, read {len(buf)})",
        )
    return buf


def unarmor_ascii_openssh_key(data):
    """
    Read the binary data from an ascii-armored OpenSSH private key file.

    :param data: String, bytes or `.read()`able
                 containing (and positioned at) an OpenSSH private key.
    :return: The raw binary data.
    """
    if isinstance(data, str):
        data = data.encode("UTF-8")

    if isinstance(data, bytes):
        fp = io.BytesIO(data)
    else:
        fp = data  # assume it's something we can `.read()`

    if not isinstance(fp, io.TextIOBase):
        fp = io.TextIOWrapper(fp, encoding="UTF-8")

    line = next(fp, "").strip()
    if line != "-----BEGIN OPENSSH PRIVATE KEY-----":
        raise ValueError(f"expected OpenSSH Private Key prelude, got {line!r}")
    lines = []
    while True:
        line = next(fp, "")
        if not line:
            raise ValueError(
                "unexpected end-of-file before OpenSSH Private Key postlude",
            )
        line = line.strip()
        if line == "-----END OPENSSH PRIVATE KEY-----":
            break
        lines.append(line)
    return base64.b64decode("".join(lines))
