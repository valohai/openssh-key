from .openssh_io import read_openssh_string


def _read_KEY_RSA(bio):
    n = read_openssh_string(bio)  # sshbuf_put_bignum2(n)
    e = read_openssh_string(bio)  # sshbuf_put_bignum2(e)
    d = read_openssh_string(bio)  # sshbuf_put_bignum2(d)
    iqmp = read_openssh_string(bio)  # sshbuf_put_bignum2(iqmp)
    p = read_openssh_string(bio)  # sshbuf_put_bignum2(p)
    q = read_openssh_string(bio)  # sshbuf_put_bignum2(q)
    return (n, e, d, iqmp, p, q)


def _read_KEY_RSA_CERT(bio):
    # TODO: test this
    read_openssh_string(bio)  # certblob
    read_openssh_string(bio)  # d
    read_openssh_string(bio)  # iqmp
    read_openssh_string(bio)  # p
    read_openssh_string(bio)  # q


def _read_KEY_DSA(bio):
    # TODO: test this
    read_openssh_string(bio)  # p
    read_openssh_string(bio)  # q
    read_openssh_string(bio)  # g
    read_openssh_string(bio)  # pubkey
    read_openssh_string(bio)  # privkey


def _read_KEY_ECDSA(bio):
    # TODO: test this
    read_openssh_string(bio)  # sshbuf_put_cstring(sshkey_curve_nid_to_name)
    read_openssh_string(
        bio
    )  # sshbuf_put_eckey -> sshbuf_put_ec -> 1 x sshbuf_put_string
    read_openssh_string(bio)  # sshbuf_put_bignum2(EC_KEY_get0_private_key)


def _read_KEY_ECDSA_CERT(bio):
    # TODO: test this
    read_openssh_string(bio)  # sshbuf_put_cstring(certblob)
    read_openssh_string(bio)  # sshbuf_put_bignum2(EC_KEY_get0_private_key)


def _read_KEY_DSA_CERT(bio):
    read_openssh_string(bio)  # sshbuf_put_cstring(certblob)
    read_openssh_string(bio)  # sshbuf_put_bignum2(dsa_priv_key)


def _read_KEY_ED25519(bio):
    read_openssh_string(bio)  # sshbuf_put_string(ed25519_pk)
    read_openssh_string(bio)  # sshbuf_put_string(ed25519_sk)


def _read_KEY_ED25519_CERT(bio):
    read_openssh_string(bio)  # sshbuf_put_cstring(certblob)
    read_openssh_string(bio)  # sshbuf_put_string(ed25519_pk)
    read_openssh_string(bio)  # sshbuf_put_string(ed25519_sk)


def _read_KEY_XMSS_CERT(bio):
    read_openssh_string(bio)  # sshbuf_put_cstring(certblob)
    read_openssh_string(bio)  # sshbuf_put_cstring(name)
    read_openssh_string(bio)  # sshbuf_put_string(pk)
    read_openssh_string(bio)  # sshbuf_put_string(sk)
    raise NotImplementedError(
        'sshkey_xmss_serialize_state_opt(): reading not supported'
    )


def _read_KEY_XMSS(bio):
    read_openssh_string(bio)  # sshbuf_put_cstring(name)
    read_openssh_string(bio)  # sshbuf_put_string(pk)
    read_openssh_string(bio)  # sshbuf_put_string(sk)
    raise NotImplementedError(
        'sshkey_xmss_serialize_state_opt(): reading not supported'
    )


_readers = {
    'ecdsa-sha2-nistp256': _read_KEY_ECDSA,
    'ecdsa-sha2-nistp256-cert-v01@openssh.com': _read_KEY_ECDSA_CERT,
    'ecdsa-sha2-nistp384': _read_KEY_ECDSA,
    'ecdsa-sha2-nistp384-cert-v01@openssh.com': _read_KEY_ECDSA_CERT,
    'ecdsa-sha2-nistp521': _read_KEY_ECDSA,
    'ecdsa-sha2-nistp521-cert-v01@openssh.com': _read_KEY_ECDSA_CERT,
    'rsa-sha2-256': _read_KEY_RSA,
    'rsa-sha2-256-cert-v01@openssh.com': _read_KEY_RSA_CERT,
    'rsa-sha2-512': _read_KEY_RSA,
    'rsa-sha2-512-cert-v01@openssh.com': _read_KEY_RSA_CERT,
    'ssh-dss': _read_KEY_DSA,
    'ssh-dss-cert-v01@openssh.com': _read_KEY_DSA_CERT,
    'ssh-ed25519': _read_KEY_ED25519,
    'ssh-ed25519-cert-v01@openssh.com': _read_KEY_ED25519_CERT,
    'ssh-rsa': _read_KEY_RSA,
    'ssh-rsa-cert-v01@openssh.com': _read_KEY_RSA_CERT,
    'ssh-xmss-cert-v01@openssh.com': _read_KEY_XMSS_CERT,
    'ssh-xmss@openssh.com': _read_KEY_XMSS,
}


def read_private_key_data(bio):
    """
    Read enough data from bio to fully read a private key.

    (The data read is thrown away, though.)

    This is required since the format does not contain the actual length
    of the privately-serialized private key data.  The knowledge of what
    to read for each key type is known by OpenSSH itself; see
    https://github.com/openssh/openssh-portable/blob/c7670b091a7174760d619ef6738b4f26b2093301/sshkey.c#L2767
    for the details.

    :param bio: Seekable binary IO object to read from
    :return: Tuple of (key format, private key data).
    """
    key_format = read_openssh_string(bio)
    start_idx = bio.tell()
    reader = _readers.get(key_format.decode())
    if not reader:
        raise NotImplementedError('Unknown key format %r' % key_format)
    reader(bio)
    end_idx = bio.tell()
    bytes_read = end_idx - start_idx
    bio.seek(start_idx)
    private_key_bytes = bio.read(bytes_read)
    return (key_format, private_key_bytes)
