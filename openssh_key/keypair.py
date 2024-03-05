import base64


class Keypair:
    """
    Encapsulates a public key, a private key and an associated comment.
    """

    # The public key material in an opaque format
    public_key = b""

    # The key format (e.g. b'ssh-rsa')
    key_format = b""

    # The private key in an opaque format dependent on key_format
    private_key = b""

    # The comment bytes, if any; defaults to b''
    comment = b""

    @property
    def public_key_string(self):
        """
        Get an "authorized_keys" style string representing the public key.
        """
        b64_pubkey = base64.b64encode(self.public_key).decode()
        comment_str = self.comment.decode("UTF-8")
        keyformat_str = self.key_format.decode()
        return f"{keyformat_str} {b64_pubkey} {comment_str}"

    def convert_to_cryptography_key(self):
        """
        Convert the key data into an usable private key object.
        """
        if self.key_format == b"ssh-rsa":
            from .cryptography_interop import _convert_rsa_private_key  # noqa: PLC0415

            return _convert_rsa_private_key(keypair=self)

        if self.key_format == b"ssh-ed25519":
            from .cryptography_interop import _convert_ed25519  # noqa: PLC0415

            return _convert_ed25519(keypair=self)

        raise NotImplementedError(
            f"Unable to convert {self.key_format} keys",
        )
