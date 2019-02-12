import io
import struct

from .excs import CipherNotSupported
from .keypair import Keypair
from .private_keys import read_private_key_data
from .openssh_io import read_openssh_string, unarmor_ascii_openssh_key

AUTH_MAGIC = b"openssh-key-v1\0"


class OpenSSHKeyFile:
    """
    Encapsulates a number of OpenSSH keys.
    """

    # The cipher used to encrypt this file.
    # At least b'none' and b'aes256-ctr' are known to exist.
    cipher_name = b''

    # The key derivation function used for the cipher's key material.
    # In the PROTOCOL.key file, b'none' or b'bcrypt' are specified.
    kdf_name = b''

    # KDF-specific options for the KDF.
    kdf_options = b''

    # The number of keys in this file.
    num_keys = 0

    # A list of bytestrings describing the public keys in this file;
    # accessible without knowing a passphrase.
    public_keys = ()

    # A (possibly) encrypted blob of private key data;
    # use .decrypt_keypairs() to parse this.
    encrypted_private_keys = None

    @classmethod
    def parse_binary(cls, binary_data):
        """
        Parse the binary data for an openssh key structure.

        The format is described in
        https://github.com/openssh/openssh-portable/blob/5c68ea8da790d711e6dd5f4c30d089c54032c59a/PROTOCOL.key
        """
        bio = io.BytesIO(binary_data)
        header = bio.read(len(AUTH_MAGIC))
        if header != AUTH_MAGIC:
            raise ValueError(
                'data began with %r, not %r' % (header, AUTH_MAGIC)
            )
        kf = cls()
        kf.cipher_name = read_openssh_string(bio)
        kf.kdf_name = read_openssh_string(bio)
        kf.kdf_options = read_openssh_string(bio)
        kf.num_keys, = struct.unpack('!I', bio.read(4))
        kf.public_keys = [read_openssh_string(bio) for x in range(kf.num_keys)]
        kf.encrypted_private_keys = read_openssh_string(bio)
        leftover = bio.read()
        if leftover:
            raise ValueError(
                'not all data was read (left over: %r)' % leftover
            )
        return kf

    @classmethod
    def parse_text(cls, data):
        """
        Parse ASCII-armored ("-----BEGIN OPENSSH PRIVATE KEY-----")
        text into an OpenSSHKeyFile object.

        :param data: String, bytes or filelike with a
                     textual OpenSSH private key.
        """
        return cls.parse_binary(unarmor_ascii_openssh_key(data))

    def decrypt_keypairs(self, passphrase=None):
        """
        Generate decrypted keypairs from the file's contents.

        :param passphrase: The passphrase required to decrypt the file.
        :return: Generator of Keypair objects.
        """
        if self.cipher_name == b'none':
            decrypted_private_keys = self.encrypted_private_keys
        else:
            # TODO: support ciphers and populate decrypted_private_key here
            raise CipherNotSupported(
                'The %r cipher is not yet supported' % self.cipher_name
            )

        bio = io.BytesIO(decrypted_private_keys)
        checkint1, checkint2 = struct.unpack('!II', bio.read(8))
        if checkint1 != checkint2:
            raise ValueError(
                'checkint mismatch: %08x != %08x' % (checkint1, checkint2)
            )
        for public_key in self.public_keys:
            kp = Keypair()
            kp.public_key = public_key
            kp.key_format, kp.private_key = read_private_key_data(bio)
            kp.comment = read_openssh_string(bio)
            yield kp
