"""
Enhanced test suite for the libit library with multi-cryptocurrency support.
Run with: python -m pytest tests_enhanced.py -v
"""

import pytest
from libit import (
    # New multi-crypto functions
    gen_key,
    multi_wallet,
    btc_wallet,
    ltc_wallet,
    doge_wallet,
    bch_wallet,
    dash_wallet,
    eth_wallet,
    trx_wallet,
    # Validation functions
    check_addr,
    is_valid,
    get_coin_type,
    Validator,
    # Legacy support
    Bitcoin,
    generate_bitcoin_wallet,
    # Data classes
    WalletInfo,
    AddressSet,
    ValidationResult,
)


class TestMultiCrypto:
    """Test multi-cryptocurrency functionality."""

    def setup_method(self):
        """Setup test data."""
        self.test_private_key = (
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        )

    def test_private_key_generation(self):
        """Test secure private key generation."""
        key = gen_key()
        assert len(key) == 64
        assert isinstance(key, str)
        # Should generate different keys
        key2 = gen_key()
        assert key != key2

    def test_bitcoin_wallet(self):
        """Test Bitcoin wallet generation."""
        wallet = btc_wallet(self.test_private_key)
        assert isinstance(wallet, WalletInfo)
        assert wallet.private_key == self.test_private_key
        assert wallet.network == "Bitcoin"
        assert isinstance(wallet.addresses, AddressSet)
        assert wallet.addresses.legacy.startswith("1")
        assert wallet.addresses.script.startswith("3")

    def test_litecoin_wallet(self):
        """Test Litecoin wallet generation."""
        wallet = ltc_wallet(self.test_private_key)
        assert isinstance(wallet, WalletInfo)
        assert wallet.network == "Litecoin"
        assert wallet.addresses.legacy.startswith("L")
        assert wallet.addresses.script.startswith("M")

    def test_dogecoin_wallet(self):
        """Test Dogecoin wallet generation."""
        wallet = doge_wallet(self.test_private_key)
        assert isinstance(wallet, WalletInfo)
        assert wallet.network == "Dogecoin"
        assert wallet.addresses.legacy.startswith("D")
        assert wallet.addresses.script.startswith("9")

    def test_bitcoin_cash_wallet(self):
        """Test Bitcoin Cash wallet generation."""
        wallet = bch_wallet(self.test_private_key)
        assert isinstance(wallet, WalletInfo)
        assert wallet.network == "Bitcoin Cash"
        assert wallet.addresses.legacy.startswith("1")
        assert wallet.addresses.script.startswith("3")

    def test_dash_wallet(self):
        """Test Dash wallet generation."""
        wallet = dash_wallet(self.test_private_key)
        assert isinstance(wallet, WalletInfo)
        assert wallet.network == "Dash"
        assert wallet.addresses.legacy.startswith("X")
        assert wallet.addresses.script.startswith("7")

    def test_ethereum_wallet(self):
        """Test Ethereum wallet generation."""
        wallet = eth_wallet(self.test_private_key)
        assert isinstance(wallet, dict)
        assert "address" in wallet
        assert wallet["address"].startswith("0x")
        assert len(wallet["address"]) == 42

    def test_tron_wallet(self):
        """Test Tron wallet generation."""
        wallet = trx_wallet(self.test_private_key)
        assert isinstance(wallet, dict)
        assert "address" in wallet
        assert wallet["address"].startswith("T")
        assert len(wallet["address"]) == 34


class TestMultiWallet:
    """Test MultiWallet class."""

    def setup_method(self):
        """Setup test data."""
        self.test_private_key = (
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        )
        self.wallet = multi_wallet(self.test_private_key)

    def test_multi_wallet_creation(self):
        """Test multi-wallet creation."""
        assert self.wallet.private_key == self.test_private_key

    def test_all_coin_access(self):
        """Test accessing all supported coins."""
        btc = self.wallet.btc()
        ltc = self.wallet.ltc()
        doge = self.wallet.doge()
        eth = self.wallet.eth()
        trx = self.wallet.trx()

        assert isinstance(btc, WalletInfo)
        assert isinstance(ltc, WalletInfo)
        assert isinstance(doge, WalletInfo)
        assert isinstance(eth, dict)
        assert isinstance(trx, dict)

    def test_all_coins_method(self):
        """Test getting all coins at once."""
        all_coins = self.wallet.all_coins()

        assert "btc" in all_coins
        assert "ltc" in all_coins
        assert "doge" in all_coins
        assert "bch" in all_coins
        assert "dash" in all_coins
        assert "eth" in all_coins
        assert "trx" in all_coins


class TestValidation:
    """Test address validation functionality."""

    def test_bitcoin_validation(self):
        """Test Bitcoin address validation."""
        # Valid P2PKH
        result = check_addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        assert result.valid == True
        assert result.coin == "btc"
        assert result.addr_type == "legacy"

        # Valid SegWit
        result = check_addr("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
        assert result.valid == True
        assert result.coin == "btc"
        assert result.addr_type == "segwit_v0"

    def test_ethereum_validation(self):
        """Test Ethereum address validation."""
        result = check_addr("0x742d35cc6500000000000000000000000000000000")
        assert result.valid == True
        assert result.coin == "eth"

    def test_invalid_address(self):
        """Test invalid address handling."""
        result = check_addr("invalid_address")
        assert result.valid == False
        assert result.coin is None

    def test_is_valid_function(self):
        """Test quick validation function."""
        assert is_valid("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") == True
        assert is_valid("invalid_address") == False

    def test_get_coin_type(self):
        """Test coin type detection."""
        assert get_coin_type("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") == "btc"
        assert get_coin_type("0x742d35cc6500000000000000000000000000000000") == "eth"
        assert get_coin_type("invalid") is None


class TestDataClasses:
    """Test data class functionality."""

    def test_wallet_info_dataclass(self):
        """Test WalletInfo dataclass."""
        addresses = AddressSet(legacy="1ABC", script="3XYZ")
        wallet_info = WalletInfo(
            private_key="test_key",
            wif="test_wif",
            decimal=12345,
            addresses=addresses,
            network="Test",
        )

        assert wallet_info.private_key == "test_key"
        assert wallet_info.addresses.legacy == "1ABC"
        assert wallet_info.compressed == True  # default value

    def test_validation_result_dataclass(self):
        """Test ValidationResult dataclass."""
        result = ValidationResult(
            address="1ABC", valid=True, coin="btc", addr_type="legacy"
        )

        assert result.address == "1ABC"
        assert result.valid == True
        assert result.coin == "btc"


class TestBulkOperations:
    """Test bulk wallet generation."""

    def test_bulk_wallet_generation(self):
        """Test generating multiple wallets."""
        from libit import gen_wallets

        wallets = gen_wallets(5, "btc")
        assert len(wallets) == 5

        for wallet in wallets:
            assert isinstance(wallet, WalletInfo)
            assert wallet.network == "Bitcoin"

    def test_bulk_multi_wallets(self):
        """Test generating multiple multi-wallets."""
        from libit import gen_multi_wallets

        wallets = gen_multi_wallets(3)
        assert len(wallets) == 3

        for wallet in wallets:
            assert "btc" in wallet
            assert "eth" in wallet
            assert "trx" in wallet


class TestBackwardCompatibility:
    """Test backward compatibility with legacy functions."""

    def test_legacy_bitcoin_class(self):
        """Test legacy Bitcoin class still works."""
        private_key = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        wallet = Bitcoin(private_key)

        addresses = wallet.get_all_addresses()
        assert "p2pkh" in addresses
        assert "p2sh" in addresses
        assert "p2wpkh" in addresses
        assert "p2wsh" in addresses

    def test_legacy_functions(self):
        """Test legacy functions still work."""
        from libit import privatekey_addr, generate_bitcoin_wallet

        # Legacy function
        addr = privatekey_addr(
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        )
        assert addr.startswith("1")

        # Legacy generator
        wallet = generate_bitcoin_wallet()
        assert "private_key" in wallet
        assert "addresses" in wallet


class TestErrorHandling:
    """Test error handling and edge cases."""

    def test_invalid_private_key(self):
        """Test invalid private key handling."""
        with pytest.raises(ValueError):
            btc_wallet("invalid_key")

        with pytest.raises(ValueError):
            btc_wallet("12345")  # Too short

    def test_unsupported_coin(self):
        """Test unsupported coin handling."""
        from libit.coins import Crypto

        with pytest.raises(ValueError):
            Crypto(
                "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                "unsupported",
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
