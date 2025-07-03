"""
Bitcoin wallet address generation module.
Supports multiple address formats: P2PKH, P2SH, P2WPKH, P2WSH.
"""

import hashlib
import struct
from typing import Optional, Dict, Any
import ecdsa
from .bs58 import b58encode_check, b58decode
from .asset import (
    MAIN_PREFIX,
    MAIN_SUFFIX,
    COMPRESSED_PREFIX,
    COMPRESSED_PREFIX2,
    UNCOMPRESSED_PREFIX,
    MAIN_DIGEST_RMD160,
)


def double_sha256(data: bytes) -> bytes:
    """Double SHA256 hash."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def hash160(data: bytes) -> bytes:
    """RIPEMD160(SHA256(data))."""
    sha256_hash = hashlib.sha256(data).digest()
    ripemd160 = hashlib.new("ripemd160")
    ripemd160.update(sha256_hash)
    return ripemd160.digest()


def bech32_polymod(values):
    """Internal function for bech32 encoding."""
    GEN = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp):
    """Expand the HRP into values for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_verify_checksum(hrp, data):
    """Verify a checksum given HRP and converted data characters."""
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1


def bech32_create_checksum(hrp, data):
    """Compute the checksum values given HRP and data."""
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32_encode(hrp, data):
    """Compute a Bech32 string given HRP and data values."""
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + "1" + "".join([bech32_charset[d] for d in combined])


def convertbits(data, frombits, tobits, pad=True):
    """Convert between bit groups."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


bech32_charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


class Bitcoin:
    """Bitcoin wallet class supporting multiple address formats."""

    def __init__(self, private_key: str):
        """
        Initialize Bitcoin wallet with private key.

        Args:
            private_key: Hexadecimal private key string (64 characters)
        """
        if len(private_key) != 64:
            raise ValueError("Private key must be 64 hexadecimal characters")

        self.private_key = private_key
        self._private_key_bytes = bytes.fromhex(private_key)
        self._public_key_compressed = None
        self._public_key_uncompressed = None

    def get_private_key(self) -> str:
        """Get the private key in hexadecimal format."""
        return self.private_key

    def get_private_key_bytes(self) -> bytes:
        """Get the private key as bytes."""
        return self._private_key_bytes

    def get_decimal(self) -> int:
        """Get the private key as decimal integer."""
        return int(self.private_key, 16)

    def get_wif(self, compressed: bool = True) -> str:
        """
        Get Wallet Import Format (WIF) of the private key.

        Args:
            compressed: Whether to use compressed format

        Returns:
            WIF string
        """
        if compressed:
            extended_key = MAIN_PREFIX + self._private_key_bytes + MAIN_SUFFIX
        else:
            extended_key = MAIN_PREFIX + self._private_key_bytes

        checksum = double_sha256(extended_key)[:4]
        return b58encode_check(extended_key + checksum).decode("utf-8")

    def get_public_key(self, compressed: bool = True) -> bytes:
        """
        Get public key from private key.

        Args:
            compressed: Whether to return compressed public key

        Returns:
            Public key bytes
        """
        if compressed and self._public_key_compressed is not None:
            return self._public_key_compressed
        elif not compressed and self._public_key_uncompressed is not None:
            return self._public_key_uncompressed

        sk = ecdsa.SigningKey.from_string(
            self._private_key_bytes, curve=ecdsa.SECP256k1
        )
        vk = sk.get_verifying_key()

        if compressed:
            prefix = (
                COMPRESSED_PREFIX2
                if vk.pubkey.point.y() % 2 == 0
                else COMPRESSED_PREFIX
            )
            self._public_key_compressed = prefix + vk.to_string()[:32]
            return self._public_key_compressed
        else:
            self._public_key_uncompressed = UNCOMPRESSED_PREFIX + vk.to_string()
            return self._public_key_uncompressed

    def get_p2pkh_address(self, compressed: bool = True) -> str:
        """
        Generate Pay-to-Public-Key-Hash (P2PKH) address.
        Legacy address format starting with '1'.

        Args:
            compressed: Whether to use compressed public key

        Returns:
            P2PKH address string
        """
        public_key = self.get_public_key(compressed)
        hash160_result = hash160(public_key)
        versioned_payload = b"\x00" + hash160_result
        return b58encode_check(versioned_payload).decode("utf-8")

    def get_p2sh_address(self, compressed: bool = True) -> str:
        """
        Generate Pay-to-Script-Hash (P2SH) address.
        Script address format starting with '3'.

        Args:
            compressed: Whether to use compressed public key

        Returns:
            P2SH address string
        """
        public_key = self.get_public_key(compressed)
        # Create a simple P2PKH script for demonstration
        script = b"\x76\xa9\x14" + hash160(public_key) + b"\x88\xac"
        script_hash = hash160(script)
        versioned_payload = b"\x05" + script_hash
        return b58encode_check(versioned_payload).decode("utf-8")

    def get_p2wpkh_address(self, compressed: bool = True) -> str:
        """
        Generate Pay-to-Witness-Public-Key-Hash (P2WPKH) address.
        Native SegWit address format starting with 'bc1'.

        Args:
            compressed: Whether to use compressed public key

        Returns:
            P2WPKH address string
        """
        public_key = self.get_public_key(compressed)
        hash160_result = hash160(public_key)

        # Convert to 5-bit groups for bech32
        converted = convertbits(hash160_result, 8, 5)
        if converted is None:
            raise ValueError("Failed to convert bits for bech32 encoding")

        # Witness version 0 + data
        witness_program = [0] + converted
        return bech32_encode("bc", witness_program)

    def get_p2wsh_address(self, compressed: bool = True) -> str:
        """
        Generate Pay-to-Witness-Script-Hash (P2WSH) address.
        Native SegWit script address format starting with 'bc1'.

        Args:
            compressed: Whether to use compressed public key

        Returns:
            P2WSH address string
        """
        public_key = self.get_public_key(compressed)
        # Create a simple P2PKH script for demonstration
        script = b"\x76\xa9\x14" + hash160(public_key) + b"\x88\xac"
        script_hash = hashlib.sha256(script).digest()

        # Convert to 5-bit groups for bech32
        converted = convertbits(script_hash, 8, 5)
        if converted is None:
            raise ValueError("Failed to convert bits for bech32 encoding")

        # Witness version 0 + data
        witness_program = [0] + converted
        return bech32_encode("bc", witness_program)

    def get_all_addresses(self, compressed: bool = True) -> Dict[str, str]:
        """
        Get all supported address formats.

        Args:
            compressed: Whether to use compressed public key

        Returns:
            Dictionary with all address types
        """
        return {
            "p2pkh": self.get_p2pkh_address(compressed),
            "p2sh": self.get_p2sh_address(compressed),
            "p2wpkh": self.get_p2wpkh_address(compressed),
            "p2wsh": self.get_p2wsh_address(compressed),
        }

    def get_wallet_info(self, compressed: bool = True) -> Dict[str, Any]:
        """
        Get comprehensive wallet information.

        Args:
            compressed: Whether to use compressed public key

        Returns:
            Dictionary with complete wallet information
        """
        addresses = self.get_all_addresses(compressed)

        return {
            "private_key": self.private_key,
            "private_key_decimal": self.get_decimal(),
            "wif": self.get_wif(compressed),
            "public_key": self.get_public_key(compressed).hex(),
            "compressed": compressed,
            "addresses": addresses,
        }


# Convenience functions for backward compatibility and ease of use
def private_key_to_p2pkh(private_key: str, compressed: bool = True) -> str:
    """Convert private key to P2PKH address."""
    wallet = Bitcoin(private_key)
    return wallet.get_p2pkh_address(compressed)


def private_key_to_p2sh(private_key: str, compressed: bool = True) -> str:
    """Convert private key to P2SH address."""
    wallet = Bitcoin(private_key)
    return wallet.get_p2sh_address(compressed)


def private_key_to_p2wpkh(private_key: str, compressed: bool = True) -> str:
    """Convert private key to P2WPKH address."""
    wallet = Bitcoin(private_key)
    return wallet.get_p2wpkh_address(compressed)


def private_key_to_p2wsh(private_key: str, compressed: bool = True) -> str:
    """Convert private key to P2WSH address."""
    wallet = Bitcoin(private_key)
    return wallet.get_p2wsh_address(compressed)


def private_key_to_all_addresses(
    private_key: str, compressed: bool = True
) -> Dict[str, str]:
    """Convert private key to all address formats."""
    wallet = Bitcoin(private_key)
    return wallet.get_all_addresses(compressed)


def private_key_to_wallet_info(
    private_key: str, compressed: bool = True
) -> Dict[str, Any]:
    """Get complete wallet information from private key."""
    wallet = Bitcoin(private_key)
    return wallet.get_wallet_info(compressed)
