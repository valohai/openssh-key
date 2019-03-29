import os

import pytest

from openssh_key.excs import CipherNotSupported
from openssh_key.keyfile import AUTH_MAGIC, OpenSSHKeyFile
from openssh_key.openssh_io import unarmor_ascii_openssh_key

rsa_key_path = os.path.realpath(
    os.path.join(os.path.dirname(__file__), 'insecure-test.ssh2')
)
rsa_pub_path = os.path.realpath(
    os.path.join(os.path.dirname(__file__), 'insecure-test.pub')
)
rsa_pem_path = os.path.realpath(
    os.path.join(os.path.dirname(__file__), 'insecure-test.pem')
)
enc_key_path = os.path.realpath(
    os.path.join(os.path.dirname(__file__), 'insecure-encrypted-test.ssh2')
)
ed25519_key_path = os.path.realpath(
    os.path.join(os.path.dirname(__file__), 'insecure-ed25519-test.ssh2')
)
ed25519_pub_path = os.path.realpath(
    os.path.join(os.path.dirname(__file__), 'insecure-ed25519-test.pub')
)


def test_unarmor():
    with open(rsa_key_path, 'rb') as infp:
        bin_data = unarmor_ascii_openssh_key(infp)
        assert bin_data.startswith(AUTH_MAGIC)

    assert (
        unarmor_ascii_openssh_key(
            '-----BEGIN OPENSSH PRIVATE KEY-----\naGVsbG8=\n-----END OPENSSH PRIVATE KEY-----'
        )
        == b'hello'
    )

    assert (
        unarmor_ascii_openssh_key(
            '-----BEGIN OPENSSH PRIVATE KEY-----\nd29ybGQ=\n-----END OPENSSH PRIVATE KEY-----'
        )
        == b'world'
    )


def test_read_rsa():
    with open(rsa_key_path, 'rb') as infp:
        ki = OpenSSHKeyFile.parse_text(infp)
    keypairs = list(ki.decrypt_keypairs())
    assert len(keypairs) == 1
    keypair = keypairs[0]
    assert keypair.key_format == b'ssh-rsa'
    with open(rsa_pub_path, 'rt') as infp:
        pub_data = infp.read().strip()
        assert keypair.public_key_string == pub_data


def test_read_encrypted():
    with open(enc_key_path, 'rb') as infp:
        ki = OpenSSHKeyFile.parse_text(infp)
        with pytest.raises(CipherNotSupported):
            list(ki.decrypt_keypairs())


def test_convert_rsa():
    try:
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        pytest.skip('the cryptography library is required for this test')
        return
    with open(rsa_key_path, 'rb') as infp:
        ki = OpenSSHKeyFile.parse_text(infp)
    keypairs = list(ki.decrypt_keypairs())
    keypair = keypairs[0]
    private_key_obj = keypair.convert_to_cryptography_key()

    # Test that we can convert back into PEM

    pem_private = private_key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(rsa_pem_path, 'rb') as infp:
        assert infp.read() == pem_private

    # Test that we can convert the public SSH part correctly too

    public_key = private_key_obj.public_key()
    ssh_public = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    ).decode()
    assert keypair.public_key_string.startswith(ssh_public)

    with open(rsa_pub_path, 'rt') as infp:
        assert infp.read().startswith(ssh_public)


def test_convert_ed25519():
    try:
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        pytest.skip('the cryptography library is required for this test')
        return
    with open(ed25519_key_path, 'rb') as infp:
        ki = OpenSSHKeyFile.parse_text(infp)
    keypairs = list(ki.decrypt_keypairs())
    keypair = keypairs[0]
    private_key_obj = keypair.convert_to_cryptography_key()
    assert private_key_obj.public_key()  # smoke test :shrug:

    with open(ed25519_pub_path, 'rt') as infp:
        assert infp.read().startswith(keypair.public_key_string)
