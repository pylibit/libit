import struct

import ecdsa
from binascii import unhexlify, hexlify
from Crypto.Hash import keccak
import hashlib
from .bs58 import b58encode_check, b58encode, b58decode
from .asset import *


class wallet:
    def __init__(self):
        super().__init__()

    def double_sha256(self, data):
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()

    def bytes_to_wif(self, private_key, compress=True):
        if compress:
            EXTENDED_KEY = MAIN_PREFIX + private_key + MAIN_SUFFIX
        else:
            EXTENDED_KEY = MAIN_PREFIX + private_key

        DOUBLE_SHA256 = self.double_sha256(EXTENDED_KEY)
        CHECKSUM = DOUBLE_SHA256[:4]

        WIF = b58encode(EXTENDED_KEY + CHECKSUM)

        return WIF.decode('utf-8')

    def bytes_to_int(self, seed) -> int:
        return int.from_bytes(seed, byteorder='big')

    def bytes_to_public(self, seed: bytes, compress: bool = True) -> bytes:
        sk = ecdsa.SigningKey.from_string(seed, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        if compress:
            prefix = COMPRESSED_PREFIX2 if vk.pubkey.point.y() % 2 == 0 else COMPRESSED_PREFIX
            return prefix + vk.to_string()[:32]
        else:
            return UNCOMPRESSED_PREFIX + vk.to_string()

    def to_hex(self, data):
        return hashlib.sha256(data.encode()).hexdigest()

    def to_bytes(self, data) -> bytes:
        return bytes.fromhex(data)

    def hex_to_bytes(self, hexed):
        return unhexlify(hexed)

    def bytes_to_hex(self, seed: bytes) -> str:
        hexed = seed.hex()
        if len(hexed) < 64:
            hexed = "0" * (64 - len(hexed)) + hexed
        elif len(hexed) > 64:
            hexed = hexed[0:64]
        return hexed

    def pub_to_addr(self, public_key: bytes) -> str:
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(hashlib.sha256(public_key).digest())
        hashed = MAIN_DIGEST_RMD160 + ripemd160.digest()
        checksum = hashlib.sha256(hashlib.sha256(hashed).digest()).digest()[:4]
        address = hashed + checksum
        return b58encode(address).decode('utf-8')

    def pass_to_addr(self, passphrase, compress=False):
        passBytes = bytes.fromhex(self.to_hex(passphrase))
        sk = ecdsa.SigningKey.from_string(passBytes, curve=ecdsa.SECP256k1)
        vk = sk.verifying_key
        if compress:
            if vk.pubkey.point.y() & 1:
                pub_key = COMPRESSED_PREFIX + vk.to_string()[:32]
            else:
                pub_key = COMPRESSED_PREFIX2 + vk.to_string()[:32]
        else:
            pub_key = UNCOMPRESSED_PREFIX + vk.to_string()
        sha = hashlib.sha256(pub_key).digest()
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha)

        address = b58encode_check(ripemd160.digest())
        return "1" + address

    def int_to_bytes(self, int_dec: int) -> bytes:
        bytes_length = (int_dec.bit_length() + 7) // 8
        return int_dec.to_bytes(bytes_length, 'big')

    def int_to_hex(self, dec: int) -> str:
        return "%064x" % dec

    def wif_to_bytes(self, wif) -> bytes:
        wif_bytes = b58decode(wif)
        isCompress = wif_bytes[-5] == 0x01 if len(wif_bytes) == 38 else False
        return wif_bytes[1:-5] if isCompress else wif_bytes[1:-4]


class ethereum:
    def __int__(self):
        super().__init__()

    def hex_to_eth(self, key_string):

        keybytes = bytes.fromhex(key_string)

        sk = ecdsa.SigningKey.from_string(keybytes, curve=ecdsa.SECP256k1)
        key = sk.get_verifying_key()
        KEY = key.to_string()
        Keccak = keccak.new(digest_bits=256)
        Keccak.update(KEY)
        pub_key = Keccak.digest()
        primitive_addr = b'\4' + pub_key[-20:]
        hashaddr = primitive_addr.hex()
        chkSum = hashaddr[0:2]
        if hashaddr[0:2] == "04":
            return "0x" + hashaddr[2:]
        else:
            raise ValueError("hash address format is invalid.")


class tron:
    def __init__(self):
        super().__init__()

    def hex_to_tron(self, key_string):
        keybytes = bytes.fromhex(key_string)

        sk = ecdsa.SigningKey.from_string(keybytes, curve=ecdsa.SECP256k1)
        key = sk.get_verifying_key()
        KEY = key.to_string()
        Keccak = keccak.new(digest_bits=256)
        Keccak.update(KEY)
        pub_key = Keccak.digest()
        primitive_addr = b'\x41' + pub_key[-20:]
        addr = b58encode_check(primitive_addr)
        return addr.decode()


tron = tron()
ethereum = ethereum()
wallet = wallet()


def bytes_wif(seed: bytes, compress: bool = False) -> str:
    return wallet.bytes_to_wif(seed, compress)


def hex_bytes(hex_string: str) -> bytes:
    return bytes.fromhex(hex_string)


def privatekey_wif(privateHex: str, compress: bool = False) -> str:
    """
    convert a private key to wif
    Args:
        privateHex:
        compress:

    Returns:
        wif:

    >>> privateHex = "12345567890abcdef..1234567890abcdef"
    >>> wif = privatekey_wif(privateHex)

    """
    seed = wallet.hex_to_bytes(privateHex)
    return wallet.bytes_to_wif(seed, compress)


def privatekey_decimal(privateHex: str) -> int:
    """

    convert a private key to decimal
    Args:
        privateHex:

    Returns:
        int:

    >>> privateHex = "12345567890abcdef..1234567890abcdef"
    >>> decimal = privatekey_decimal(privateHex)
    """
    return int(privateHex, 16)


def bytes_addr(seed: bytes, compress: bool = False) -> str:
    """

    Args:
        seed:
        compress:

    Returns:
        addr:

    >>> seed_bytes = "HERE BYTES 32"
    >>> compress_address = bytes_addr(seed_bytes, True)
    >>> uncompress_address = bytes_addr(seed_bytes)
    """
    pb = wallet.bytes_to_public(seed, compress)
    return wallet.pub_to_addr(pb)


def wif_addr(wif: str, compress: bool = False) -> str:
    """

    Args:
        wif:
        compress:

    Returns:
        addr:

    >>> wif = "5KMnkl,,,,,,MNadh"
    >>> compress_address = wif_addr(wif, True)
    >>> uncompress_address = wif_addr(wif)
    """
    seed = wallet.wif_to_bytes(wif)
    return bytes_addr(seed, compress)


def privatekey_addr(hex_string: str, compress: bool = False) -> str:
    """

    Args:
        hex_string:
        compress:

    Returns:
        addr:

    >>> hex_string = "12345567890abcdef..1234567890abcdef"
    >>> compress_address = privatekey_addr(hex_string, True)
    >>> uncompress_address = privatekey_addr(hex_string)
    """
    seed = hex_bytes(hex_string)
    return bytes_addr(seed, compress)


def passphrase_addr(passphrase: str, compress: bool = False) -> str:
    """

    Args:
        passphrase:
        compress:

    Returns:
        addr:

    >>> passphrase = "Mmdrza.Com"
    >>> compress_address = passphrase_addr(passphrase, True)
    >>> uncompress_address = passphrase_addr(passphrase)
    """
    return wallet.pass_to_addr(passphrase, compress)


def dec_addr(dec: int, compress: bool = False) -> str:
    """

    Args:
        dec:
        compress:

    Returns:
        addr:

    >>> dec = 12345567890
    >>> compress_address = dec_addr(dec, True)
    >>> uncompress_address = dec_addr(dec)
    """
    seed = wallet.int_to_bytes(dec)
    return bytes_addr(seed, compress)


def bytes_eth(seed: bytes) -> str:
    """

    Args:
        seed:

    Returns:
        eth_addr:

    >>> seed_bytes = "HERE BYTES 32"
    >>> eth_address = bytes_eth(seed_bytes)
    """
    return eth_addr(wallet.bytes_to_hex(seed))


def eth_addr(hex_string: str):
    """

    Args:
        hex_string:

    Returns:
        eth_addr:

    >>> hex_string = "12345567890abcdef..1234567890abcdef"
    >>> eth_address = eth_addr(hex_string)

    """
    return ethereum.hex_to_eth(hex_string)


def dec_eth(dec: int) -> str:
    """

    Args:
        dec:

    Returns:
        eth_addr:

    >>> dec = 12345567890
    >>> eth_address = dec_eth(dec)
    """
    return eth_addr(wallet.int_to_hex(dec))


def bytes_trx(seed: bytes) -> str:
    """

    Args:
        seed:

    Returns:
        trx_addr:

    >>> seed_bytes = "HERE BYTES 32"
    >>> trx_address = bytes_trx(seed_bytes)

    """
    return trx_addr(wallet.bytes_to_hex(seed))


def trx_addr(hex_string: str):
    """

    Args:
        hex_string:

    Returns:
        trx_addr:

    >>> hex_string = "12345567890abcdef..1234567890abcdef"
    >>> trx_address = trx_addr(hex_string)

    """
    return tron.hex_to_tron(hex_string)


def dec_trx(dec: int) -> str:
    """

    Args:
        dec:

    Returns:
        trx_addr:

    >>> dec = 12345567890
    >>> tron_address = dec_trx(dec)

    """
    return trx_addr(wallet.int_to_hex(dec))
