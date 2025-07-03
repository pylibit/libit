import struct

import ecdsa
from binascii import unhexlify, hexlify
from Crypto.Hash import keccak
import hashlib
from .bs58 import b58encode_check, b58encode, b58decode
from .asset import *


def double_sha256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def sha256_hex(data):
    return hashlib.sha256(bytes.fromhex(data)).hexdigest()


def bytes_to_wif(private_key, compress=True) -> str:
    if compress:
        EXTENDED_KEY = MAIN_PREFIX + private_key + MAIN_SUFFIX
    else:
        EXTENDED_KEY = MAIN_PREFIX + private_key

    DOUBLE_SHA256 = double_sha256(EXTENDED_KEY)
    CHECKSUM = DOUBLE_SHA256[:4]

    WIF = b58encode(EXTENDED_KEY + CHECKSUM)

    return WIF.decode('utf-8')


def bytes_to_int(seed) -> int:
    return int.from_bytes(seed, byteorder='big')


def bytes_to_public(seed: bytes, compress: bool = True) -> bytes:
    sk = ecdsa.SigningKey.from_string(seed, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    if compress:
        prefix = COMPRESSED_PREFIX2 if vk.pubkey.point.y() % 2 == 0 else COMPRESSED_PREFIX
        return prefix + vk.to_string()[:32]
    else:
        return UNCOMPRESSED_PREFIX + vk.to_string()


def to_hex(data: str) -> str:
    """
    converting dats words example passphrase or ... to hexadecimal.

    Args:
        data:

    Returns:
        hexed
    """
    data = data.encode()
    dt256 = hashlib.sha256(data)
    return dt256.hexdigest()


def to_bytes(data: str) -> bytes:
    return bytes.fromhex(data)


def hex_to_bytes(hexed: str) -> bytes:
    return unhexlify(hexed)


def bytes_to_hex(seed: bytes) -> str:
    hexed = seed.hex()
    if len(hexed) < 64:
        hexed = "0" * (64 - len(hexed)) + hexed
    elif len(hexed) > 64:
        hexed = hexed[0:64]
    return hexed


def pub_to_addr(public_key: bytes) -> str:
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(public_key).digest())
    hashed = MAIN_DIGEST_RMD160 + ripemd160.digest()
    checksum = hashlib.sha256(hashlib.sha256(hashed).digest()).digest()[:4]
    address = hashed + checksum
    return b58encode(address).decode('utf-8')


def pass_to_addr(passphrase, compress=False):
    passBytes = bytes.fromhex(to_hex(passphrase))
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

    addHash = b58encode_check(ripemd160.digest())
    addEnc = addHash.decode()
    return f"1{addEnc}"


def int_to_bytes(int_dec: int) -> bytes:
    bytes_length = (int_dec.bit_length() + 7) // 8
    return int_dec.to_bytes(bytes_length, 'big')


def int_to_hex(dec: int) -> str:
    return "%064x" % dec


def wif_to_bytes(wif) -> bytes:
    """
    convert wif to bytes

    Args:
        wif:

    Returns:
        bytes
    """
    wif_bytes = b58decode(wif)
    isCompress = wif_bytes[-5] == 0x01 if len(wif_bytes) == 38 else False
    return wif_bytes[1:-5] if isCompress else wif_bytes[1:-4]


def hex_to_eth(key_string):
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


class Ethereum:
    def __init__(self, private_key: str):
        self.private_key = private_key

    def get_address(self) -> str:
        return hex_to_eth(self.private_key)

    def get_decimal(self) -> int:
        return int(self.private_key, 16)

    def get_seed(self) -> bytes:
        return bytes.fromhex(self.private_key)

    def get_hexAddress(self) -> str:
        return self.private_key




def hex_to_tron(key_string):
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


def hex_addr_tron(address: str):
    return b58decode(address).hex()[:-8]


class tron:
    def __init__(self, private_key: str):
        self.private_key = private_key

    def get_address(self) -> str:
        return hex_to_tron(self.private_key)

    def get_decimal(self) -> int:
        return int(self.private_key, 16)

    def get_seed(self) -> bytes:
        return bytes.fromhex(self.private_key)

    def get_hexAddress(self) -> str:
        address = tron(self.private_key).get_address()
        return hex_addr_tron(address)

    def get_evmAddress(self) -> str:
        """  return hex address like ethereum address wallet """
        hex_addr = tron(self.private_key).get_hexAddress()
        return "0x" + hex_addr[2:]


def bytes_wif(seed: bytes, compress: bool = False) -> str:
    """
    convert bytes to wif compressed or uncompressed.

    Args:
        seed:
        compress:

    Returns:
        wif

    """
    return bytes_to_wif(seed, compress)


def hex_bytes(hex_string: str) -> bytes:
    """
    convert hex string to bytes.

    Args:
        hex_string:

    Returns:
        bytes

    """
    return bytes.fromhex(hex_string)


def privatekey_wif(privateHex: str, compress: bool = False) -> str:
    """
    convert a private key to wif
    Args:
        privateHex:
        compress:

    Returns:
        wif
    """
    seed = hex_to_bytes(privateHex)
    return bytes_to_wif(seed, compress)


def privatekey_decimal(privateHex: str) -> int:
    """

    convert a private key to decimal
    Args:
        privateHex:

    Returns:
        int
    """
    return int(privateHex, 16)


def bytes_addr(seed: bytes, compress: bool = False) -> str:
    """

    Args:
        seed:
        compress:

    Returns:
        addr
    """
    pb = bytes_to_public(seed, compress)
    return pub_to_addr(pb)


def wif_addr(wif: str, compress: bool = False) -> str:
    """

    Args:
        wif:
        compress:

    Returns:
        addr
    """
    seed = wif_to_bytes(wif)
    return bytes_addr(seed, compress)


def privatekey_addr(hex_string: str, compress: bool = False) -> str:
    """

    Args:
        hex_string:
        compress:

    Returns:
        addr
    """
    seed = hex_bytes(hex_string)
    return bytes_addr(seed, compress)


def passphrase_addr(passphrase: str, compress: bool = False) -> str:
    """

    Args:
        passphrase:
        compress:

    Returns:
        addr
    """
    return pass_to_addr(passphrase, compress)


def dec_addr(dec: int, compress: bool = False) -> str:
    """

    Args:
        dec:
        compress:

    Returns:
        addr
    """
    seed = int_to_bytes(dec)
    return bytes_addr(seed, compress)


def bytes_eth(seed: bytes) -> str:
    """

    Args:
        seed:

    Returns:
        eth_addr
    """
    return eth_addr(bytes_to_hex(seed))


def eth_addr(hex_string: str):
    """

    Args:
        hex_string:

    Returns:
        eth_addr

    """
    return ethereum.hex_to_eth(hex_string)


def dec_eth(dec: int) -> str:
    """

    Args:
        dec:

    Returns:
        eth_addr
    """
    return eth_addr(int_to_hex(dec))


def bytes_trx(seed: bytes) -> str:
    """

    Args:
        seed:

    Returns:
        trx_addr

    """
    trx = tron(bytes_to_hex(seed))
    return trx.get_address()


def trx_addr(hex_string: str):
    """

    Args:
        hex_string:

    Returns:
        trx_addr

    """
    trx = tron(hex_string)
    return trx.address()


def dec_trx(dec: int) -> str:
    """

    Args:
        dec:

    Returns:
        trx_addr

    """
    trx = tron(int_to_hex(dec))
    return trx.get_address()


def trx_hash(address: str):
    """

    Args:
        address:

    Returns:
        trx_addr

    """
    if address[0] == "T":
        return hex_addr_tron(address)
    else:
        return "check address format"


def trx_hex(address: str):
    """

    Args:
        address:

    Returns:
        trx_addr

    """
    if address[0] == "T":
        return "0x" + hex_addr_tron(address)[2:]
    else:
        return "check address format"
