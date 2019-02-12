import base64


class Keypair:
    public_key: bytes = None  # The public key
    key_format: bytes = None  # The key format
    private_key: bytes = None  # The private key in a private serialization format dependent on key_format
    comment: bytes = None  # The comment

    @property
    def public_key_string(self):
        return '%s %s %s' % (
            self.key_format.decode(),
            base64.b64encode(self.public_key).decode(),
            self.comment.decode('UTF-8'),
        )

    def convert_to_cryptography_key(self):
        if self.key_format == b'ssh-rsa':
            from .cryptography_interop import convert_rsa_private_key

            return convert_rsa_private_key(keypair=self)
        raise NotImplementedError('Unable to convert %s keys' % self.key_format)
