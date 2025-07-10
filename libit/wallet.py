"""
Wallet generation utilities for multiple cryptocurrencies.
Provides unified interface for Bitcoin, Ethereum, and Tron wallet generation.
"""
import hashlib
import hmac
import secrets
import os
from typing import Dict, Any, Optional, List
from .bitcoin import Bitcoin
from .lib import Ethereum, tron


class WalletGenerator:
    """Unified wallet generator for multiple cryptocurrencies."""

    @staticmethod
    def generate_private_key() -> str:
        """
        Generate a cryptographically secure random private key.

        Returns:
            64-character hexadecimal private key string
        """
        return secrets.randbits(256).to_bytes(32, "big").hex()

    @staticmethod
    def from_entropy(entropy: bytes) -> str:
        """
        Generate private key from entropy bytes.

        Args:
            entropy: 32 bytes of entropy

        Returns:
            64-character hexadecimal private key string
        """
        if len(entropy) != 32:
            raise ValueError("Entropy must be exactly 32 bytes")
        return entropy.hex()

    @staticmethod
    def from_seed_phrase(seed_phrase: str, passphrase: str = "") -> str:
        """
        Generate private key from BIP39 seed phrase.

        Args:
            seed_phrase: BIP39 mnemonic phrase
            passphrase: Optional passphrase

        Returns:
            64-character hexadecimal private key string
        """
        # Simple implementation - in production, use proper BIP39 library
        seed = hashlib.pbkdf2_hmac(
            "sha512",
            seed_phrase.encode("utf-8"),
            f"mnemonic{passphrase}".encode("utf-8"),
            2048,
        )
        return seed[:32].hex()

    @classmethod
    def generate_bitcoin_wallet(cls, compressed: bool = True) -> Dict[str, Any]:
        """
        Generate a complete Bitcoin wallet.

        Args:
            compressed: Whether to use compressed public keys

        Returns:
            Dictionary with complete Bitcoin wallet information
        """
        private_key = cls.generate_private_key()
        bitcoin_wallet = Bitcoin(private_key)
        return bitcoin_wallet.get_wallet_info(compressed)

    @classmethod
    def generate_ethereum_wallet(cls) -> Dict[str, Any]:
        """
        Generate a complete Ethereum wallet.

        Returns:
            Dictionary with Ethereum wallet information
        """
        private_key = cls.generate_private_key()
        eth_wallet = Ethereum(private_key)

        return {
            "private_key": private_key,
            "private_key_decimal": eth_wallet.get_decimal(),
            "address": eth_wallet.get_address(),
            "network": "ethereum",
        }

    @classmethod
    def generate_tron_wallet(cls) -> Dict[str, Any]:
        """
        Generate a complete Tron wallet.

        Returns:
            Dictionary with Tron wallet information
        """
        private_key = cls.generate_private_key()
        tron_wallet = tron(private_key)

        return {
            "private_key": private_key,
            "private_key_decimal": tron_wallet.get_decimal(),
            "address": tron_wallet.get_address(),
            "hex_address": tron_wallet.get_hexAddress(),
            "evm_address": tron_wallet.get_evmAddress(),
            "network": "tron",
        }

    @classmethod
    def generate_multi_wallet(
        cls, compressed: bool = True
    ) -> Dict[str, Dict[str, Any]]:
        """
        Generate wallets for Bitcoin, Ethereum, and Tron using the same private key.

        Args:
            compressed: Whether to use compressed public keys for Bitcoin

        Returns:
            Dictionary with wallets for all supported networks
        """
        private_key = cls.generate_private_key()

        # Bitcoin wallet
        bitcoin_wallet = Bitcoin(private_key)
        bitcoin_info = bitcoin_wallet.get_wallet_info(compressed)

        # Ethereum wallet
        eth_wallet = Ethereum(private_key)
        ethereum_info = {
            "private_key": private_key,
            "private_key_decimal": eth_wallet.get_decimal(),
            "address": eth_wallet.get_address(),
            "network": "ethereum",
        }

        # Tron wallet
        tron_wallet = tron(private_key)
        tron_info = {
            "private_key": private_key,
            "private_key_decimal": tron_wallet.get_decimal(),
            "address": tron_wallet.get_address(),
            "hex_address": tron_wallet.get_hexAddress(),
            "evm_address": tron_wallet.get_evmAddress(),
            "network": "tron",
        }

        return {"bitcoin": bitcoin_info, "ethereum": ethereum_info, "tron": tron_info}

    @classmethod
    def from_private_key(
        cls, private_key: str, compressed: bool = True
    ) -> Dict[str, Dict[str, Any]]:
        """
        Generate wallets for all networks from existing private key.

        Args:
            private_key: 64-character hexadecimal private key
            compressed: Whether to use compressed public keys for Bitcoin

        Returns:
            Dictionary with wallets for all supported networks
        """
        if len(private_key) != 64:
            raise ValueError("Private key must be 64 hexadecimal characters")

        # Bitcoin wallet
        bitcoin_wallet = Bitcoin(private_key)
        bitcoin_info = bitcoin_wallet.get_wallet_info(compressed)

        # Ethereum wallet
        eth_wallet = Ethereum(private_key)
        ethereum_info = {
            "private_key": private_key,
            "private_key_decimal": eth_wallet.get_decimal(),
            "address": eth_wallet.get_address(),
            "network": "ethereum",
        }

        # Tron wallet
        tron_wallet = tron(private_key)
        tron_info = {
            "private_key": private_key,
            "private_key_decimal": tron_wallet.get_decimal(),
            "address": tron_wallet.get_address(),
            "hex_address": tron_wallet.get_hexAddress(),
            "evm_address": tron_wallet.get_evmAddress(),
            "network": "tron",
        }

        return {"bitcoin": bitcoin_info, "ethereum": ethereum_info, "tron": tron_info}


class BulkWalletGenerator:
    """Bulk wallet generation utilities."""

    @staticmethod
    def generate_bitcoin_wallets(
        count: int, compressed: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Generate multiple Bitcoin wallets.

        Args:
            count: Number of wallets to generate
            compressed: Whether to use compressed public keys

        Returns:
            List of Bitcoin wallet dictionaries
        """
        wallets = []
        for _ in range(count):
            wallets.append(WalletGenerator.generate_bitcoin_wallet(compressed))
        return wallets

    @staticmethod
    def generate_ethereum_wallets(count: int) -> List[Dict[str, Any]]:
        """
        Generate multiple Ethereum wallets.

        Args:
            count: Number of wallets to generate

        Returns:
            List of Ethereum wallet dictionaries
        """
        wallets = []
        for _ in range(count):
            wallets.append(WalletGenerator.generate_ethereum_wallet())
        return wallets

    @staticmethod
    def generate_tron_wallets(count: int) -> List[Dict[str, Any]]:
        """
        Generate multiple Tron wallets.

        Args:
            count: Number of wallets to generate

        Returns:
            List of Tron wallet dictionaries
        """
        wallets = []
        for _ in range(count):
            wallets.append(WalletGenerator.generate_tron_wallet())
        return wallets

    @staticmethod
    def generate_multi_wallets(
        count: int, compressed: bool = True
    ) -> List[Dict[str, Dict[str, Any]]]:
        """
        Generate multiple multi-network wallets.

        Args:
            count: Number of multi-wallets to generate
            compressed: Whether to use compressed public keys for Bitcoin

        Returns:
            List of multi-wallet dictionaries
        """
        wallets = []
        for _ in range(count):
            wallets.append(WalletGenerator.generate_multi_wallet(compressed))
        return wallets


# Convenience functions
def generate_private_key() -> str:
    """Generate a cryptographically secure private key."""
    return WalletGenerator.generate_private_key()


def generate_bitcoin_wallet(compressed: bool = True) -> Dict[str, Any]:
    """Generate a Bitcoin wallet."""
    return WalletGenerator.generate_bitcoin_wallet(compressed)


def generate_ethereum_wallet() -> Dict[str, Any]:
    """Generate an Ethereum wallet."""
    return WalletGenerator.generate_ethereum_wallet()


def generate_tron_wallet() -> Dict[str, Any]:
    """Generate a Tron wallet."""
    return WalletGenerator.generate_tron_wallet()


def generate_multi_wallet(compressed: bool = True) -> Dict[str, Dict[str, Any]]:
    """Generate multi-network wallet."""
    return WalletGenerator.generate_multi_wallet(compressed)


def from_private_key(
    private_key: str, compressed: bool = True
) -> Dict[str, Dict[str, Any]]:
    """Generate wallets from existing private key."""
    return WalletGenerator.from_private_key(private_key, compressed)
