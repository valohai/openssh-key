import gzip
import pathlib

import pytest

from openssh_key.excs import CipherNotSupported
from openssh_key.keyfile import AUTH_MAGIC, OpenSSHKeyFile
from openssh_key.openssh_io import convert_openssl_unsigned_bn_binary_to_int, unarmor_ascii_openssh_key

tests_path = pathlib.Path(__file__).parent.resolve()
rsa_key_path = tests_path / "insecure-test.ssh2"
rsa_pub_path = tests_path / "insecure-test.pub"
rsa_pem_path = tests_path / "insecure-test.pem"
enc_key_path = tests_path / "insecure-encrypted-test.ssh2"
ed25519_key_path = tests_path / "insecure-ed25519-test.ssh2"
ed25519_pub_path = tests_path / "insecure-ed25519-test.pub"
bn_dumps_path = tests_path / "bn_dumps.txt.gz"


def test_unarmor():
    with rsa_key_path.open("rb") as infp:
        bin_data = unarmor_ascii_openssh_key(infp)
        assert bin_data.startswith(AUTH_MAGIC)

    assert (
        unarmor_ascii_openssh_key(
            "-----BEGIN OPENSSH PRIVATE KEY-----\naGVsbG8=\n-----END OPENSSH PRIVATE KEY-----",
        )
        == b"hello"
    )

    assert (
        unarmor_ascii_openssh_key(
            "-----BEGIN OPENSSH PRIVATE KEY-----\nd29ybGQ=\n-----END OPENSSH PRIVATE KEY-----",
        )
        == b"world"
    )


def test_read_rsa():
    with rsa_key_path.open("rb") as infp:
        ki = OpenSSHKeyFile.parse_text(infp)
    keypairs = list(ki.decrypt_keypairs())
    assert len(keypairs) == 1
    keypair = keypairs[0]
    assert keypair.key_format == b"ssh-rsa"
    assert keypair.public_key_string == rsa_pub_path.read_text().strip()


def test_read_encrypted():
    with enc_key_path.open("rb") as infp:
        ki = OpenSSHKeyFile.parse_text(infp)
        with pytest.raises(CipherNotSupported):
            list(ki.decrypt_keypairs())


def test_convert_rsa():
    serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization")
    with rsa_key_path.open("rb") as infp:
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
    assert pem_private == rsa_pem_path.read_bytes()

    # Test that we can convert the public SSH part correctly too

    public_key = private_key_obj.public_key()
    ssh_public = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    ).decode()
    assert keypair.public_key_string.startswith(ssh_public)
    assert rsa_pub_path.read_text().startswith(ssh_public)


def test_convert_ed25519():
    pytest.importorskip("cryptography.hazmat.primitives.serialization")
    with ed25519_key_path.open("rb") as infp:
        ki = OpenSSHKeyFile.parse_text(infp)
    keypairs = list(ki.decrypt_keypairs())
    keypair = keypairs[0]
    private_key_obj = keypair.convert_to_cryptography_key()
    assert private_key_obj.public_key()  # smoke test :shrug:

    assert ed25519_pub_path.read_text().startswith(keypair.public_key_string)


def test_bn():
    if not bn_dumps_path.exists():
        pytest.skip("No bn_dumps.txt.gz file; run make in the tests directory")
    with gzip.GzipFile(bn_dumps_path, "rb") as infp:
        for line in infp:
            nbits, bnhex, dec = line.strip().split()
            bnbin = bytes.fromhex(bnhex.decode())
            assert convert_openssl_unsigned_bn_binary_to_int(bnbin) == int(dec)
