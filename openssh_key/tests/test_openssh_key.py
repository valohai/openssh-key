import os

import pytest

from openssh_key.keyfile import AUTH_MAGIC, OpenSSHKeyFile
from openssh_key.openssh_io import unarmor_ascii_openssh_key

key_path = os.path.realpath(os.path.join(os.path.dirname(__file__), 'insecure-test.ssh2'))
pub_path = os.path.realpath(os.path.join(os.path.dirname(__file__), 'insecure-test.pub'))


def test_unarmor():
    with open(key_path, 'rb') as infp:
        bin_data = unarmor_ascii_openssh_key(infp)
        assert bin_data.startswith(AUTH_MAGIC)


def test_read():
    with open(key_path, 'rb') as infp:
        ki = OpenSSHKeyFile.parse_text(infp)
    keypairs = list(ki.decrypt_keypairs())
    assert len(keypairs) == 1
    keypair = keypairs[0]
    assert keypair.key_format == b'ssh-rsa'
    with open(pub_path, 'rt') as infp:
        pub_data = infp.read().strip()
        assert keypair.public_key_string == pub_data
