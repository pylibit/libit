import hashlib, ecdsa, struct
from Crypto.Hash import keccak
from .bs58 import b58encode_check, b58encode, b58decode
from .asset import *


def sha256_hex(data):
    return hashlib.sha256(bytes.fromhex(data)).hexdigest()


def hex_to_tron(key_string: str) -> str:
    """
        convert hex string to tron address

        :param key_string:
        :type key_string: str
        :return address:
        :rtype: str
        """
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


class Wallet:

    @staticmethod
    def get_address(private_key: str) -> str:
        return hex_to_tron(private_key)

    @staticmethod
    def get_decimal(private_key: str) -> int:
        return int(private_key, 16)

    @staticmethod
    def get_hashAddress(address: str) -> str:
        """
        convert tron address to hash string format start with 41.

        :param address:
        :return: hash string
        """
        return hex_addr_tron(address)

    @staticmethod
    def get_hexAddress(address: str) -> str:
        """  return hex address like ethereum address wallet """
        return "0x" + hex_addr_tron(address)[2:]
