import base64
import io
import struct


def read_openssh_string(bin_fp):
    """
    Read a length-prefixed ("OpenSSH-style Pascal") string from the given binary fp.

    This format is described in https://tools.ietf.org/html/rfc4251
    (look for "Arbitrary length binary string").

    :param bin_fp:
    :return: bytes
    """
    length, = struct.unpack('!I', bin_fp.read(4))
    buf = bin_fp.read(length)
    if len(buf) != length:
        raise ValueError('short read for string (expected %d bytes, read %d)' % (length, len(buf)))
    return buf


def unarmor_ascii_openssh_key(data):
    """
    Read the binary data from an ascii-armored OpenSSH private key file.

    :param data: String, bytes or `.read()`able containing (and positioned at)
                 an OpenSSH private key.
    :return: The raw binary data.
    """
    if isinstance(data, str):
        fp = io.StringIO(data.encode('UTF-8'))
    elif isinstance(data, bytes):
        fp = io.BytesIO(data)
    else:
        fp = data  # assume it's something we can `.read()`

    if not isinstance(fp, io.TextIOBase):
        fp = io.TextIOWrapper(fp, encoding='UTF-8')

    line = next(fp)
    if line != '-----BEGIN OPENSSH PRIVATE KEY-----\n':
        raise ValueError('expected OpenSSH Private Key prelude, got %r' % line)
    lines = []
    while True:
        line = next(fp)
        if not line:
            raise ValueError('unexpected end-of-file before OpenSSH Private Key postlude')
        if line == '-----END OPENSSH PRIVATE KEY-----\n':
            break
        lines.append(line)
    return base64.b64decode(''.join(lines))
