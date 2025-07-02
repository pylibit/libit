"""
Utility functions for cryptographic operations and address validation.
"""

import re
import hashlib
from typing import Union, Tuple, Optional
from .bs58 import b58decode, b58encode_check


def is_valid_private_key(private_key: str) -> bool:
    """
    Validate if a string is a valid private key.

    Args:
        private_key: String to validate

    Returns:
        True if valid private key, False otherwise
    """
    if not isinstance(private_key, str):
        return False

    # Check if it's 64 hex characters
    if len(private_key) != 64:
        return False

    # Check if it's valid hex
    try:
        int(private_key, 16)
    except ValueError:
        return False

    # Check if it's in valid range (not zero, not greater than curve order)
    private_key_int = int(private_key, 16)
    if private_key_int == 0:
        return False

    # secp256k1 curve order
    curve_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140
    if private_key_int >= curve_order:
        return False

    return True


def is_valid_bitcoin_address(address: str) -> Tuple[bool, Optional[str]]:
    """
    Validate Bitcoin address and return its type.

    Args:
        address: Bitcoin address string

    Returns:
        Tuple of (is_valid, address_type)
    """
    if not isinstance(address, str):
        return False, None

    # P2PKH addresses (start with 1)
    if address.startswith("1"):
        try:
            decoded = b58decode(address)
            if len(decoded) != 25:
                return False, None

            # Check version byte
            if decoded[0] != 0x00:
                return False, None

            # Verify checksum
            payload = decoded[:-4]
            checksum = decoded[-4:]
            calculated_checksum = hashlib.sha256(
                hashlib.sha256(payload).digest()
            ).digest()[:4]

            if checksum == calculated_checksum:
                return True, "P2PKH"
            return False, None
        except:
            return False, None

    # P2SH addresses (start with 3)
    elif address.startswith("3"):
        try:
            decoded = b58decode(address)
            if len(decoded) != 25:
                return False, None

            # Check version byte
            if decoded[0] != 0x05:
                return False, None

            # Verify checksum
            payload = decoded[:-4]
            checksum = decoded[-4:]
            calculated_checksum = hashlib.sha256(
                hashlib.sha256(payload).digest()
            ).digest()[:4]

            if checksum == calculated_checksum:
                return True, "P2SH"
            return False, None
        except:
            return False, None

    # Bech32 addresses (start with bc1)
    elif address.startswith("bc1"):
        # Simple length check for bech32 validation
        if 14 <= len(address) <= 74:
            # P2WPKH addresses are typically 42 characters
            if len(address) == 42:
                return True, "P2WPKH"
            # P2WSH addresses are typically 62 characters
            elif len(address) == 62:
                return True, "P2WSH"
            else:
                return True, "Bech32"
        return False, None

    return False, None


def is_valid_ethereum_address(address: str) -> bool:
    """
    Validate Ethereum address.

    Args:
        address: Ethereum address string

    Returns:
        True if valid Ethereum address, False otherwise
    """
    if not isinstance(address, str):
        return False

    # Check if it starts with 0x and is 42 characters long
    if not address.startswith("0x") or len(address) != 42:
        return False

    # Check if the rest are valid hex characters
    try:
        int(address[2:], 16)
        return True
    except ValueError:
        return False


def is_valid_tron_address(address: str) -> bool:
    """
    Validate Tron address.

    Args:
        address: Tron address string

    Returns:
        True if valid Tron address, False otherwise
    """
    if not isinstance(address, str):
        return False

    # Tron addresses start with 'T' and are 34 characters long
    if not address.startswith("T") or len(address) != 34:
        return False

    try:
        # Try to decode with base58
        decoded = b58decode(address)
        if len(decoded) != 25:  # 21 bytes + 4 bytes checksum
            return False

        # Check if first byte is 0x41 (Tron mainnet)
        if decoded[0] != 0x41:
            return False

        # Verify checksum
        payload = decoded[:-4]
        checksum = decoded[-4:]
        calculated_checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[
            :4
        ]

        return checksum == calculated_checksum
    except:
        return False


def format_private_key(private_key: Union[str, int, bytes]) -> str:
    """
    Format private key to standard 64-character hex string.

    Args:
        private_key: Private key in various formats

    Returns:
        64-character hex string
    """
    if isinstance(private_key, str):
        # Remove 0x prefix if present
        if private_key.startswith("0x"):
            private_key = private_key[2:]

        # Pad with zeros if necessary
        return private_key.zfill(64).lower()

    elif isinstance(private_key, int):
        return f"{private_key:064x}"

    elif isinstance(private_key, bytes):
        return private_key.hex().zfill(64)

    else:
        raise ValueError("Unsupported private key format")


def compress_public_key(public_key: bytes) -> bytes:
    """
    Compress an uncompressed public key.

    Args:
        public_key: Uncompressed public key (65 bytes)

    Returns:
        Compressed public key (33 bytes)
    """
    if len(public_key) != 65 or public_key[0] != 0x04:
        raise ValueError("Invalid uncompressed public key")

    x = public_key[1:33]
    y = public_key[33:65]

    # Check if y is even or odd
    y_int = int.from_bytes(y, "big")
    if y_int % 2 == 0:
        return b"\x02" + x
    else:
        return b"\x03" + x


def decompress_public_key(public_key: bytes) -> bytes:
    """
    Decompress a compressed public key.

    Args:
        public_key: Compressed public key (33 bytes)

    Returns:
        Uncompressed public key (65 bytes)
    """
    if len(public_key) != 33:
        raise ValueError("Invalid compressed public key length")

    if public_key[0] not in [0x02, 0x03]:
        raise ValueError("Invalid compressed public key prefix")

    # This is a simplified implementation
    # In practice, you would use elliptic curve point decompression
    # For now, raise NotImplementedError
    raise NotImplementedError("Public key decompression requires elliptic curve math")


def secure_random_bytes(length: int) -> bytes:
    """
    Generate cryptographically secure random bytes.

    Args:
        length: Number of bytes to generate

    Returns:
        Random bytes
    """
    import secrets

    return secrets.token_bytes(length)


def entropy_to_private_key(entropy: Union[str, bytes]) -> str:
    """
    Convert entropy to private key using SHA256.

    Args:
        entropy: Entropy as string or bytes

    Returns:
        64-character hex private key
    """
    if isinstance(entropy, str):
        entropy = entropy.encode("utf-8")

    private_key_bytes = hashlib.sha256(entropy).digest()
    return private_key_bytes.hex()


class AddressValidator:
    """Utility class for address validation."""

    @staticmethod
    def validate_bitcoin(address: str) -> dict:
        """
        Comprehensive Bitcoin address validation.

        Args:
            address: Bitcoin address

        Returns:
            Dictionary with validation results
        """
        is_valid, addr_type = is_valid_bitcoin_address(address)
        return {
            "address": address,
            "is_valid": is_valid,
            "type": addr_type,
            "network": "bitcoin" if is_valid else None,
        }

    @staticmethod
    def validate_ethereum(address: str) -> dict:
        """
        Ethereum address validation.

        Args:
            address: Ethereum address

        Returns:
            Dictionary with validation results
        """
        is_valid = is_valid_ethereum_address(address)
        return {
            "address": address,
            "is_valid": is_valid,
            "type": "ethereum" if is_valid else None,
            "network": "ethereum" if is_valid else None,
        }

    @staticmethod
    def validate_tron(address: str) -> dict:
        """
        Tron address validation.

        Args:
            address: Tron address

        Returns:
            Dictionary with validation results
        """
        is_valid = is_valid_tron_address(address)
        return {
            "address": address,
            "is_valid": is_valid,
            "type": "tron" if is_valid else None,
            "network": "tron" if is_valid else None,
        }

    @staticmethod
    def validate_any(address: str) -> dict:
        """
        Validate address for any supported network.

        Args:
            address: Address string

        Returns:
            Dictionary with validation results
        """
        # Try Bitcoin first
        btc_result = AddressValidator.validate_bitcoin(address)
        if btc_result["is_valid"]:
            return btc_result

        # Try Ethereum
        eth_result = AddressValidator.validate_ethereum(address)
        if eth_result["is_valid"]:
            return eth_result

        # Try Tron
        tron_result = AddressValidator.validate_tron(address)
        if tron_result["is_valid"]:
            return tron_result

        # Invalid for all networks
        return {"address": address, "is_valid": False, "type": None, "network": None}
