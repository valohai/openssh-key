import base64


class Keypair:
    """
    Encapsulates a public key, a private key and an associated comment.
    """

    # The public key material in an opaque format
    public_key = b''

    # The key format (e.g. b'ssh-rsa')
    key_format = b''

    # The private key in an opaque format dependent on key_format
    private_key = b''

    # The comment bytes, if any; defaults to b''
    comment = b''

    @property
    def public_key_string(self):
        """
        Get an "authorized_keys" style string representing the public key.
        """
        return '%s %s %s' % (
            self.key_format.decode(),
            base64.b64encode(self.public_key).decode(),
            self.comment.decode('UTF-8'),
        )

    def convert_to_cryptography_key(self):
        """
        Convert the key data into an usable private key object.
        """
        if self.key_format == b'ssh-rsa':
            from .cryptography_interop import _convert_rsa_private_key

            return _convert_rsa_private_key(keypair=self)
        raise NotImplementedError(
            'Unable to convert %s keys' % self.key_format
        )
