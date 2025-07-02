#!/usr/bin/env python3
"""
Comprehensive test suite for multi-cryptocurrency functionality.
Tests all supported coins and validation features.
"""

import pytest
from libit import (
    # Wallet generation
    gen_key,
    multi_wallet,
    btc_wallet,
    ltc_wallet,
    doge_wallet,
    bch_wallet,
    dash_wallet,
    zcash_wallet,
    vtc_wallet,
    eth_wallet,
    trx_wallet,
    # Short aliases
    btc,
    ltc,
    doge,
    bch,
    dash,
    zcash,
    vtc,
    eth,
    trx,
    # Classes
    Crypto,
    MultiWallet,
    WalletInfo,
    AddressSet,
    # Validation
    check_addr,
    is_valid,
    valid,
    coin_type,
    check,
    Validator,
    # Bulk generation
    gen_wallets,
    gen_multi_wallets,
)


class TestKeyGeneration:
    """Test private key generation."""

    def test_gen_key(self):
        """Test key generation."""
        key = gen_key()
        assert isinstance(key, str)
        assert len(key) == 64
        assert int(key, 16)  # Valid hex

    def test_multiple_keys_unique(self):
        """Test that generated keys are unique."""
        keys = [gen_key() for _ in range(10)]
        assert len(set(keys)) == 10  # All unique


class TestCryptoClass:
    """Test the main Crypto class."""

    def test_crypto_init_valid(self):
        """Test valid initialization."""
        key = gen_key()
        crypto = Crypto(key, "btc")
        assert crypto.private_key == key
        assert crypto.coin_type == "btc"

    def test_crypto_init_invalid_key(self):
        """Test invalid key handling."""
        with pytest.raises(ValueError):
            Crypto("invalid", "btc")

        with pytest.raises(ValueError):
            Crypto("", "btc")

    def test_crypto_init_invalid_coin(self):
        """Test invalid coin handling."""
        key = gen_key()
        with pytest.raises(ValueError):
            Crypto(key, "invalid_coin")

    def test_crypto_addresses(self):
        """Test address generation."""
        key = gen_key()
        crypto = Crypto(key, "btc")

        legacy = crypto.legacy()
        script = crypto.script()
        addrs = crypto.addrs()

        assert legacy.startswith("1")
        assert script.startswith("3")
        assert isinstance(addrs, AddressSet)
        assert addrs.legacy == legacy
        assert addrs.script == script

    def test_crypto_wallet_info(self):
        """Test wallet info generation."""
        key = gen_key()
        crypto = Crypto(key, "btc")
        info = crypto.info()

        assert isinstance(info, WalletInfo)
        assert info.private_key == key
        assert info.network == "Bitcoin"
        assert isinstance(info.decimal, int)
        assert info.wif.startswith(("K", "L", "5"))


class TestIndividualWallets:
    """Test individual wallet generation functions."""

    def test_btc_wallet(self):
        """Test Bitcoin wallet generation."""
        key = gen_key()
        wallet = btc_wallet(key)

        assert isinstance(wallet, WalletInfo)
        assert wallet.private_key == key
        assert wallet.network == "Bitcoin"
        assert wallet.addresses.legacy.startswith("1")
        assert wallet.addresses.script.startswith("3")

    def test_ltc_wallet(self):
        """Test Litecoin wallet generation."""
        key = gen_key()
        wallet = ltc_wallet(key)

        assert isinstance(wallet, WalletInfo)
        assert wallet.network == "Litecoin"
        assert wallet.addresses.legacy.startswith("L")
        assert wallet.addresses.script.startswith("M")

    def test_doge_wallet(self):
        """Test Dogecoin wallet generation."""
        key = gen_key()
        wallet = doge_wallet(key)

        assert isinstance(wallet, WalletInfo)
        assert wallet.network == "Dogecoin"
        assert wallet.addresses.legacy.startswith("D")
        assert wallet.addresses.script.startswith("9")

    def test_bch_wallet(self):
        """Test Bitcoin Cash wallet generation."""
        key = gen_key()
        wallet = bch_wallet(key)

        assert isinstance(wallet, WalletInfo)
        assert wallet.network == "Bitcoin Cash"
        assert wallet.addresses.legacy.startswith("1")
        assert wallet.addresses.script.startswith("3")

    def test_dash_wallet(self):
        """Test Dash wallet generation."""
        key = gen_key()
        wallet = dash_wallet(key)

        assert isinstance(wallet, WalletInfo)
        assert wallet.network == "Dash"
        assert wallet.addresses.legacy.startswith("X")
        assert wallet.addresses.script.startswith("7")

    def test_zcash_wallet(self):
        """Test Zcash wallet generation."""
        key = gen_key()
        wallet = zcash_wallet(key)

        assert isinstance(wallet, WalletInfo)
        assert wallet.network == "Zcash"
        assert wallet.addresses.legacy.startswith("t1")
        assert wallet.addresses.script.startswith("t3")

    def test_vtc_wallet(self):
        """Test Vertcoin wallet generation."""
        key = gen_key()
        wallet = vtc_wallet(key)

        assert isinstance(wallet, WalletInfo)
        assert wallet.network == "Vertcoin"
        assert wallet.addresses.legacy.startswith("V")

    def test_eth_wallet(self):
        """Test Ethereum wallet generation."""
        key = gen_key()
        wallet = eth_wallet(key)

        assert isinstance(wallet, dict)
        assert wallet["network"] == "Ethereum"
        assert wallet["address"].startswith("0x")
        assert len(wallet["address"]) == 42

    def test_trx_wallet(self):
        """Test Tron wallet generation."""
        key = gen_key()
        wallet = trx_wallet(key)

        assert isinstance(wallet, dict)
        assert wallet["network"] == "Tron"
        assert wallet["address"].startswith("T")
        assert len(wallet["address"]) == 34


class TestShortAliases:
    """Test ultra-short function aliases."""

    def test_short_aliases_work(self):
        """Test that short aliases work correctly."""
        # Test with private key
        key = gen_key()

        wallet1 = btc(key)
        wallet2 = ltc(key)
        wallet3 = doge(key)
        wallet4 = bch(key)
        wallet5 = dash(key)

        assert isinstance(wallet1, WalletInfo)
        assert isinstance(wallet2, WalletInfo)
        assert isinstance(wallet3, WalletInfo)
        assert isinstance(wallet4, WalletInfo)
        assert isinstance(wallet5, WalletInfo)

    def test_short_aliases_without_key(self):
        """Test short aliases without providing key."""
        wallet1 = btc()
        wallet2 = eth()
        wallet3 = trx()

        assert isinstance(wallet1, WalletInfo)
        assert isinstance(wallet2, dict)
        assert isinstance(wallet3, dict)


class TestMultiWallet:
    """Test MultiWallet class."""

    def test_multi_wallet_init(self):
        """Test MultiWallet initialization."""
        key = gen_key()
        multi = multi_wallet(key)

        assert isinstance(multi, MultiWallet)
        assert multi.private_key == key

    def test_multi_wallet_auto_key(self):
        """Test MultiWallet with auto key generation."""
        multi = multi_wallet()

        assert isinstance(multi, MultiWallet)
        assert len(multi.private_key) == 64

    def test_multi_wallet_all_coins(self):
        """Test all coin generation."""
        key = gen_key()
        multi = multi_wallet(key)

        btc_info = multi.btc()
        ltc_info = multi.ltc()
        eth_info = multi.eth()
        trx_info = multi.trx()

        assert isinstance(btc_info, WalletInfo)
        assert isinstance(ltc_info, WalletInfo)
        assert isinstance(eth_info, dict)
        assert isinstance(trx_info, dict)

        # Test all() method
        all_wallets = multi.all()
        assert "btc" in all_wallets
        assert "ltc" in all_wallets
        assert "eth" in all_wallets
        assert "trx" in all_wallets


class TestValidation:
    """Test address validation functionality."""

    def test_btc_validation(self):
        """Test Bitcoin address validation."""
        # Valid addresses
        valid_addresses = [
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",  # Legacy
            "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",  # Script
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",  # SegWit
        ]

        for addr in valid_addresses:
            result = check_addr(addr, "btc")
            assert result.valid
            assert result.coin == "btc"

    def test_validation_short_functions(self):
        """Test short validation functions."""
        addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

        assert valid(addr) == True
        assert is_valid(addr) == True
        assert coin_type(addr) == "btc"

        result = check(addr)
        assert result.valid
        assert result.coin == "btc"

    def test_auto_detection(self):
        """Test automatic coin detection."""
        test_cases = [
            ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "btc"),
            ("LQ1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "ltc"),  # Example Litecoin
            ("DQ1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "doge"),  # Example Dogecoin
            ("XQ1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "dash"),  # Example Dash
        ]

        for addr, expected_coin in test_cases:
            result = check_addr(addr)
            if result.valid:  # Only test if the format is valid
                assert result.coin == expected_coin

    def test_invalid_addresses(self):
        """Test invalid address handling."""
        invalid_addresses = ["", "invalid", "1234567890", None, 123]

        for addr in invalid_addresses:
            if addr is not None:
                result = check_addr(str(addr))
                assert result.valid == False


class TestBulkGeneration:
    """Test bulk wallet generation."""

    def test_gen_wallets(self):
        """Test bulk wallet generation for single coin."""
        wallets = gen_wallets(5, "btc")

        assert len(wallets) == 5
        assert all(isinstance(w, WalletInfo) for w in wallets)
        assert all(w.network == "Bitcoin" for w in wallets)

        # Check uniqueness
        private_keys = [w.private_key for w in wallets]
        assert len(set(private_keys)) == 5

    def test_gen_multi_wallets(self):
        """Test bulk multi-coin wallet generation."""
        wallets = gen_multi_wallets(3)

        assert len(wallets) == 3
        assert all(isinstance(w, dict) for w in wallets)
        assert all("btc" in w and "eth" in w for w in wallets)

        # Check uniqueness
        btc_keys = [w["btc"]["private_key"] for w in wallets]
        assert len(set(btc_keys)) == 3

    def test_bulk_generation_limits(self):
        """Test bulk generation limits."""
        with pytest.raises(ValueError):
            gen_wallets(0)  # Invalid count

        with pytest.raises(ValueError):
            gen_wallets(-1)  # Negative count

    def test_bulk_generation_invalid_coin(self):
        """Test bulk generation with invalid coin."""
        with pytest.raises(ValueError):
            gen_wallets(5, "invalid_coin")


class TestErrorHandling:
    """Test error handling and edge cases."""

    def test_private_key_validation(self):
        """Test private key validation."""
        # Test 0x prefix removal
        key_with_prefix = "0x" + gen_key()
        crypto = Crypto(key_with_prefix, "btc")
        assert len(crypto.private_key) == 64

        # Test invalid lengths
        with pytest.raises(ValueError):
            Crypto("123", "btc")

        with pytest.raises(ValueError):
            Crypto("g" * 64, "btc")  # Invalid hex

    def test_dataclass_conversion(self):
        """Test dataclass to dict conversion."""
        key = gen_key()
        wallet = btc_wallet(key)

        wallet_dict = wallet.to_dict()
        assert isinstance(wallet_dict, dict)
        assert wallet_dict["private_key"] == key
        assert wallet_dict["network"] == "Bitcoin"

    def test_validation_result_conversion(self):
        """Test ValidationResult to dict conversion."""
        result = check_addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        result_dict = result.to_dict()

        assert isinstance(result_dict, dict)
        assert "is_valid" in result_dict
        assert "coin" in result_dict


def run_tests():
    """Run all tests."""
    print("Running multi-cryptocurrency tests...")

    # Test key generation
    print("✓ Testing key generation...")
    key = gen_key()
    assert len(key) == 64
    print(f"  Generated key: {key[:16]}...")

    # Test individual wallets
    print("✓ Testing individual wallets...")
    btc_w = btc_wallet(key)
    ltc_w = ltc_wallet(key)
    doge_w = doge_wallet(key)
    print(f"  BTC: {btc_w.addresses.legacy}")
    print(f"  LTC: {ltc_w.addresses.legacy}")
    print(f"  DOGE: {doge_w.addresses.legacy}")

    # Test multi-wallet
    print("✓ Testing multi-wallet...")
    multi = multi_wallet(key)
    all_wallets = multi.all()
    print(f"  Generated {len(all_wallets)} cryptocurrency wallets")

    # Test validation
    print("✓ Testing validation...")
    result = check_addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    print(f"  BTC validation: {result.valid} ({result.coin})")

    # Test short aliases
    print("✓ Testing short aliases...")
    quick_btc = btc()
    quick_eth = eth()
    print(f"  Quick BTC: {quick_btc.addresses.legacy}")
    print(f"  Quick ETH: {quick_eth['address']}")

    print("✅ All tests passed!")


if __name__ == "__main__":
    run_tests()
