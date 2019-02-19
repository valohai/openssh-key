import base64
import io
import struct


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
    length, = struct.unpack('!I', len_buf)
    buf = bin_fp.read(length)
    if len(buf) != length:
        raise ValueError(
            'short read for string (expected %d bytes, read %d)'
            % (length, len(buf))
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
        data = data.encode('UTF-8')

    if isinstance(data, bytes):
        fp = io.BytesIO(data)
    else:
        fp = data  # assume it's something we can `.read()`

    if not isinstance(fp, io.TextIOBase):
        fp = io.TextIOWrapper(fp, encoding='UTF-8')

    line = next(fp, '').strip()
    if line != '-----BEGIN OPENSSH PRIVATE KEY-----':
        raise ValueError('expected OpenSSH Private Key prelude, got %r' % line)
    lines = []
    while True:
        line = next(fp, '')
        if not line:
            raise ValueError(
                'unexpected end-of-file before OpenSSH Private Key postlude'
            )
        line = line.strip()
        if line == '-----END OPENSSH PRIVATE KEY-----':
            break
        lines.append(line)
    return base64.b64decode(''.join(lines))
