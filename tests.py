"""
Test suite for the libit library.
Run with: python -m pytest tests.py -v
"""

import pytest
from libit import (
    Bitcoin,
    WalletGenerator,
    AddressValidator,
    generate_bitcoin_wallet,
    private_key_to_all_addresses,
    is_valid_private_key,
    format_private_key,
)


class TestBitcoinWallet:
    """Test Bitcoin wallet functionality."""

    def setup_method(self):
        """Setup test data."""
        self.test_private_key = (
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        )
        self.wallet = Bitcoin(self.test_private_key)

    def test_private_key_storage(self):
        """Test private key is stored correctly."""
        assert self.wallet.get_private_key() == self.test_private_key

    def test_decimal_conversion(self):
        """Test private key to decimal conversion."""
        expected_decimal = int(self.test_private_key, 16)
        assert self.wallet.get_decimal() == expected_decimal

    def test_p2pkh_address_generation(self):
        """Test P2PKH address generation."""
        address = self.wallet.get_p2pkh_address()
        assert address.startswith("1")
        assert len(address) >= 26
        assert len(address) <= 35

    def test_p2sh_address_generation(self):
        """Test P2SH address generation."""
        address = self.wallet.get_p2sh_address()
        assert address.startswith("3")
        assert len(address) >= 26
        assert len(address) <= 35

    def test_p2wpkh_address_generation(self):
        """Test P2WPKH address generation."""
        address = self.wallet.get_p2wpkh_address()
        assert address.startswith("bc1")
        assert len(address) == 42

    def test_p2wsh_address_generation(self):
        """Test P2WSH address generation."""
        address = self.wallet.get_p2wsh_address()
        assert address.startswith("bc1")
        assert len(address) == 62

    def test_all_addresses(self):
        """Test getting all address types."""
        addresses = self.wallet.get_all_addresses()
        assert "p2pkh" in addresses
        assert "p2sh" in addresses
        assert "p2wpkh" in addresses
        assert "p2wsh" in addresses

        assert addresses["p2pkh"].startswith("1")
        assert addresses["p2sh"].startswith("3")
        assert addresses["p2wpkh"].startswith("bc1")
        assert addresses["p2wsh"].startswith("bc1")

    def test_wallet_info(self):
        """Test comprehensive wallet info."""
        info = self.wallet.get_wallet_info()
        assert "private_key" in info
        assert "private_key_decimal" in info
        assert "wif" in info
        assert "public_key" in info
        assert "addresses" in info
        assert "compressed" in info

    def test_invalid_private_key(self):
        """Test invalid private key handling."""
        with pytest.raises(ValueError):
            Bitcoin("invalid_key")

        with pytest.raises(ValueError):
            Bitcoin("12345")  # Too short


class TestWalletGenerator:
    """Test wallet generator functionality."""

    def test_generate_private_key(self):
        """Test private key generation."""
        private_key = WalletGenerator.generate_private_key()
        assert len(private_key) == 64
        assert is_valid_private_key(private_key)

    def test_generate_bitcoin_wallet(self):
        """Test Bitcoin wallet generation."""
        wallet = WalletGenerator.generate_bitcoin_wallet()
        assert "private_key" in wallet
        assert "addresses" in wallet
        assert len(wallet["private_key"]) == 64

    def test_generate_multi_wallet(self):
        """Test multi-network wallet generation."""
        wallet = WalletGenerator.generate_multi_wallet()
        assert "bitcoin" in wallet
        assert "ethereum" in wallet
        assert "tron" in wallet

    def test_from_private_key(self):
        """Test wallet generation from existing private key."""
        test_key = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        wallet = WalletGenerator.from_private_key(test_key)
        assert wallet["bitcoin"]["private_key"] == test_key
        assert wallet["ethereum"]["private_key"] == test_key
        assert wallet["tron"]["private_key"] == test_key


class TestAddressValidator:
    """Test address validation functionality."""

    def setup_method(self):
        """Setup validator."""
        self.validator = AddressValidator()

    def test_validate_bitcoin_p2pkh(self):
        """Test P2PKH address validation."""
        # Valid P2PKH addresses for testing
        valid_addresses = [
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
        ]

        for addr in valid_addresses:
            result = self.validator.validate_bitcoin(addr)
            assert result["is_valid"] == True
            assert result["type"] == "P2PKH"

    def test_validate_invalid_bitcoin(self):
        """Test invalid Bitcoin address validation."""
        invalid_addresses = [
            "invalid_address",
            "1234567890",
            "0x742d35cc6500000000000000000000000000000000000000",
        ]

        for addr in invalid_addresses:
            result = self.validator.validate_bitcoin(addr)
            assert result["is_valid"] == False


class TestUtilities:
    """Test utility functions."""

    def test_is_valid_private_key(self):
        """Test private key validation."""
        valid_key = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        assert is_valid_private_key(valid_key) == True

        invalid_keys = [
            "invalid",
            "12345",
            "0000000000000000000000000000000000000000000000000000000000000000",  # Zero
            "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",  # Invalid hex
        ]

        for key in invalid_keys:
            assert is_valid_private_key(key) == False

    def test_format_private_key(self):
        """Test private key formatting."""
        test_key = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

        # Test with 0x prefix
        formatted = format_private_key("0x" + test_key)
        assert formatted == test_key

        # Test with short key (padding)
        short_key = "12345"
        formatted = format_private_key(short_key)
        assert len(formatted) == 64
        assert formatted.endswith("12345")

    def test_convenience_functions(self):
        """Test convenience functions."""
        test_key = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

        # Test generate_bitcoin_wallet
        wallet = generate_bitcoin_wallet()
        assert "private_key" in wallet
        assert "addresses" in wallet

        # Test private_key_to_all_addresses
        addresses = private_key_to_all_addresses(test_key)
        assert "p2pkh" in addresses
        assert "p2sh" in addresses
        assert "p2wpkh" in addresses
        assert "p2wsh" in addresses


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
