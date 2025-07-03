from typing import Union, Tuple

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def check_input(r, s1, s2, z1, z2):
    if r < 0 or r > p - 1:
        return False
    if s1 < 0 or s1 > p - 1:
        return False
    if s2 < 0 or s2 > p - 1:
        return False
    if z1 < 0 or z1 > p - 1:
        return False
    if z2 < 0 or z2 > p - 1:
        return False
    return True


def inverse_mod(a, m):
    """Inverse of a mod m."""
    if a == 0:  # pragma: no branch
        return 0
    return pow(a, -1, m)


def reused(r, s1, s2, z1, z2):
    checked = check_input(r, s1, s2, z1, z2)
    if not checked:
        return False
    key = []
    for (i, j) in [(1, 1), (1, -1), (-1, 1), (-1, -1)]:
        z = z1 - z2
        s = s1 * i + s2 * j
        r_inv = inverse_mod(r, p)
        s_inv = inverse_mod(s, p)
        k = (z * s_inv) % p
        d = (r_inv * (s1 * k - z1)) % p
        draw_hex = hex(d)
        kral_hex = hex(k)
        key.append(hex(d))
    return key


def extract_key(r: int, s1: int, s2: int, z1: int, z2: int) -> Union[bool, Tuple[str, str]]:  # pragma: no cover
    """ Extract Private Key and Public Key From Signature [r, s1, s2, z1, z2]

    :param r: signature r
    :param s1: signature s1
    :param s2: signature s2
    :param z1: signature z1
    :param z2: signature z2
    :returns: private key, public key

    >>> from libit import reuse
    >>> r = 0x0861cce1da15fc2dd79f1164c4f7b3e6c1526e7e8d85716578689ca9a5dc349d
    >>> s1 = 0x6cf26e2776f7c94cafcee05cc810471ddca16fa864d13d57bee1c06ce39a3188
    >>> s2 = 0x4ba75bdda43b3aab84b895cfd9ef13a477182657faaf286a7b0d25f0cb9a7de2
    >>> z1 = 0x01b125d18422cdfa7b153f5bcf5b01927cf59791d1d9810009c70cd37b14f4e6
    >>> z2 = 0x339ff7b1ced3a45c988b3e4e239ea745db3b2b3fda6208134691bd2e4a37d6e1
    >>> private_key, public_key = reuse.extract_key(r, s1, s2, z1, z2)
    >>> private_key
    '0861cce1da15fc2dd79f1164c4f7b3e6c1526e7e8d85716578689ca9a5dc349d'
    >>> public_key
    '01b125d18422cdfa7b153f5bcf5b01927cf59791d1d9810009c70cd37b14f4e6'

    """
    if not check_input(r, s1, s2, z1, z2):
        return False
    keys = reused(r, s1, s2, z1, z2)
    private_key = keys[0][2:]
    public_key = keys[1][2:]
    return private_key, public_key


def crack_secret_from_k(generator, signed_value, sig, k):
    """
    Given a signature of a signed_value and a known k, return the secret exponent.
    """
    r, s = sig
    return ((s * k - signed_value) * generator.inverse(r)) % generator.order()


def crack_k_from_sigs(generator, sig1, val1, sig2, val2):
    """
    Given two signatures with the same secret exponent and K value, return that K value.
    """

    r1, s1 = sig1
    r2, s2 = sig2
    if r1 != r2:
        raise ValueError("r values of signature do not match")
    k = (r2 * val1 - r1 * val2) * generator.inverse(r2 * s1 - r1 * s2)
    return k % generator.order()
