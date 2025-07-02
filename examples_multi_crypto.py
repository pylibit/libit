#!/usr/bin/env python3
"""
Enhanced examples for multi-cryptocurrency wallet library.
Demonstrates all supported coins and features with shorter function names.
"""

from libit import (
    # Key generation
    gen_key,
    # Individual wallet functions
    btc_wallet,
    ltc_wallet,
    doge_wallet,
    bch_wallet,
    dash_wallet,
    zcash_wallet,
    vtc_wallet,
    eth_wallet,
    trx_wallet,
    # Ultra-short aliases
    btc,
    ltc,
    doge,
    bch,
    dash,
    zcash,
    vtc,
    eth,
    trx,
    # Multi-wallet
    multi_wallet,
    # Validation
    check_addr,
    is_valid,
    valid,
    coin_type,
    check,
    # Bulk generation
    gen_wallets,
    gen_multi_wallets,
    # Classes
    Crypto,
    MultiWallet,
    Validator,
)


def example_key_generation():
    """Example: Generate secure private keys."""
    print("🔑 Key Generation")
    print("=" * 50)

    # Generate a secure private key
    key = gen_key()
    print(f"Generated private key: {key}")
    print(f"Key length: {len(key)} characters")
    print(f"Is valid hex: {int(key, 16) > 0}")
    print()


def example_individual_wallets():
    """Example: Create wallets for individual cryptocurrencies."""
    print("🪙 Individual Cryptocurrency Wallets")
    print("=" * 50)

    # Use the same key for all wallets
    key = gen_key()
    print(f"Using private key: {key[:16]}...")
    print()

    # Bitcoin wallet
    btc_w = btc_wallet(key)
    print(f"Bitcoin (BTC):")
    print(f"  Legacy (P2PKH): {btc_w.addresses.legacy}")
    print(f"  Script (P2SH):  {btc_w.addresses.script}")
    print(f"  WIF:            {btc_w.wif}")
    print()

    # Litecoin wallet
    ltc_w = ltc_wallet(key)
    print(f"Litecoin (LTC):")
    print(f"  Legacy: {ltc_w.addresses.legacy}")
    print(f"  Script: {ltc_w.addresses.script}")
    print()

    # Dogecoin wallet
    doge_w = doge_wallet(key)
    print(f"Dogecoin (DOGE):")
    print(f"  Legacy: {doge_w.addresses.legacy}")
    print(f"  Script: {doge_w.addresses.script}")
    print()

    # Bitcoin Cash wallet
    bch_w = bch_wallet(key)
    print(f"Bitcoin Cash (BCH):")
    print(f"  Legacy: {bch_w.addresses.legacy}")
    print(f"  Script: {bch_w.addresses.script}")
    print()

    # Dash wallet
    dash_w = dash_wallet(key)
    print(f"Dash (DASH):")
    print(f"  Legacy: {dash_w.addresses.legacy}")
    print(f"  Script: {dash_w.addresses.script}")
    print()

    # Zcash wallet
    zcash_w = zcash_wallet(key)
    print(f"Zcash (ZEC):")
    print(f"  Legacy: {zcash_w.addresses.legacy}")
    print(f"  Script: {zcash_w.addresses.script}")
    print()

    # Vertcoin wallet
    vtc_w = vtc_wallet(key)
    print(f"Vertcoin (VTC):")
    print(f"  Legacy: {vtc_w.addresses.legacy}")
    print(f"  Script: {vtc_w.addresses.script}")
    print()

    # Ethereum wallet
    eth_w = eth_wallet(key)
    print(f"Ethereum (ETH):")
    print(f"  Address: {eth_w['address']}")
    print()

    # Tron wallet
    trx_w = trx_wallet(key)
    print(f"Tron (TRX):")
    print(f"  Address:     {trx_w['address']}")
    print(f"  Hex Address: {trx_w['hex_address']}")
    print(f"  EVM Address: {trx_w['evm_address']}")
    print()


def example_ultra_short_names():
    """Example: Using ultra-short function names."""
    print("⚡ Ultra-Short Function Names")
    print("=" * 50)

    print("Creating wallets with minimal code:")
    print()

    # Generate wallets with ultra-short names (auto-generates keys)
    btc_wallet = btc()
    ltc_wallet = ltc()
    doge_wallet = doge()
    eth_wallet = eth()
    trx_wallet = trx()

    print(f"btc()  → {btc_wallet.addresses.legacy}")
    print(f"ltc()  → {ltc_wallet.addresses.legacy}")
    print(f"doge() → {doge_wallet.addresses.legacy}")
    print(f"eth()  → {eth_wallet['address']}")
    print(f"trx()  → {trx_wallet['address']}")
    print()

    # You can also provide your own key
    key = gen_key()
    custom_btc = btc(key)
    custom_eth = eth(key)

    print(f"With custom key:")
    print(f"btc('{key[:16]}...') → {custom_btc.addresses.legacy}")
    print(f"eth('{key[:16]}...') → {custom_eth['address']}")
    print()


def example_multi_wallet():
    """Example: Multi-cryptocurrency wallet manager."""
    print("🌐 Multi-Cryptocurrency Wallet")
    print("=" * 50)

    # Create multi-wallet with single private key
    key = gen_key()
    multi = multi_wallet(key)

    print(f"Multi-wallet with key: {key[:16]}...")
    print()

    # Get individual cryptocurrency wallets
    btc_info = multi.btc()
    ltc_info = multi.ltc()
    eth_info = multi.eth()
    trx_info = multi.trx()

    print("Individual cryptocurrency access:")
    print(f"BTC Legacy: {btc_info.addresses.legacy}")
    print(f"LTC Legacy: {ltc_info.addresses.legacy}")
    print(f"ETH Address: {eth_info['address']}")
    print(f"TRX Address: {trx_info['address']}")
    print()

    # Get all cryptocurrencies at once
    all_wallets = multi.all()

    print("All supported cryptocurrencies:")
    for coin, wallet_info in all_wallets.items():
        if isinstance(wallet_info, dict) and "addresses" in wallet_info:
            # Cryptocurrency with multiple address types
            print(f"{coin.upper()}: {wallet_info['addresses']['legacy']}")
        elif isinstance(wallet_info, dict) and "address" in wallet_info:
            # Cryptocurrency with single address
            print(f"{coin.upper()}: {wallet_info['address']}")
    print()


def example_crypto_class():
    """Example: Using the Crypto class directly."""
    print("🔧 Using Crypto Class Directly")
    print("=" * 50)

    key = gen_key()

    # Create Bitcoin crypto instance
    btc_crypto = Crypto(key, "btc")

    print(f"Bitcoin Crypto Instance:")
    print(f"  Private Key: {btc_crypto.private_key}")
    print(f"  Legacy:      {btc_crypto.legacy()}")  # Short method
    print(f"  Script:      {btc_crypto.script()}")  # Short method
    print(f"  WIF:         {btc_crypto.wif()}")  # Short method
    print(f"  Decimal:     {btc_crypto.decimal()}")  # Short method
    print()

    # Get wallet info
    wallet_info = btc_crypto.info()  # Short method
    print(f"Wallet Info (dataclass):")
    print(f"  Network:    {wallet_info.network}")
    print(f"  Compressed: {wallet_info.compressed}")
    print(f"  Dict:       {wallet_info.to_dict()}")
    print()

    # Create Litecoin crypto instance
    ltc_crypto = Crypto(key, "ltc")
    print(f"Litecoin addresses:")
    print(f"  Legacy: {ltc_crypto.legacy()}")
    print(f"  Script: {ltc_crypto.script()}")
    print()


def example_address_validation():
    """Example: Address validation for all cryptocurrencies."""
    print("✅ Address Validation")
    print("=" * 50)

    # Test addresses for different cryptocurrencies
    test_addresses = [
        ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "Bitcoin Legacy"),
        ("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", "Bitcoin Script"),
        ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "Bitcoin SegWit"),
        ("LQfWLz9W4D8F5rxBkfKGKMuFh9Fkm9uZ7", "Litecoin"),
        ("DQE1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "Dogecoin"),
        ("XqE1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "Dash"),
        ("0x742e4DEF4A2E9FE39Bd8BF4D5F8D4B2A77B4C5A8", "Ethereum"),
        ("TQE1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "Tron"),
    ]

    print("Validating addresses:")
    for address, description in test_addresses:
        # Auto-detect validation
        result = check_addr(address)

        print(f"{description}:")
        print(f"  Address: {address}")
        print(f"  Valid:   {result.valid}")
        if result.valid:
            print(f"  Coin:    {result.coin}")
            print(f"  Type:    {result.addr_type}")
        print()

    print("Ultra-short validation functions:")
    btc_address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    print(f"valid('{btc_address[:20]}...')      → {valid(btc_address)}")
    print(f"coin_type('{btc_address[:20]}...')  → {coin_type(btc_address)}")
    print(f"check('{btc_address[:20]}...')      → {check(btc_address).coin}")
    print()


def example_validation_short_methods():
    """Example: Using Validator class short methods."""
    print("🔍 Validator Short Methods")
    print("=" * 50)

    # Generate some test addresses
    key = gen_key()
    btc_addr = btc_wallet(key).addresses.legacy
    ltc_addr = ltc_wallet(key).addresses.legacy
    doge_addr = doge_wallet(key).addresses.legacy

    print("Testing with generated addresses:")
    print(f"BTC:  {Validator.btc(btc_addr).valid}")
    print(f"LTC:  {Validator.ltc(ltc_addr).valid}")
    print(f"DOGE: {Validator.doge(doge_addr).valid}")
    print(f"Auto: {Validator.auto(btc_addr).coin}")
    print()


def example_bulk_generation():
    """Example: Bulk wallet generation."""
    print("🏭 Bulk Wallet Generation")
    print("=" * 50)

    # Generate multiple Bitcoin wallets
    btc_wallets = gen_wallets(3, "btc")
    print(f"Generated {len(btc_wallets)} Bitcoin wallets:")
    for i, wallet in enumerate(btc_wallets, 1):
        print(f"  Wallet {i}: {wallet.addresses.legacy}")
    print()

    # Generate multiple Litecoin wallets
    ltc_wallets = gen_wallets(2, "ltc")
    print(f"Generated {len(ltc_wallets)} Litecoin wallets:")
    for i, wallet in enumerate(ltc_wallets, 1):
        print(f"  Wallet {i}: {wallet.addresses.legacy}")
    print()

    # Generate multi-cryptocurrency wallets
    multi_wallets = gen_multi_wallets(2)
    print(f"Generated {len(multi_wallets)} multi-crypto wallets:")
    for i, wallet in enumerate(multi_wallets, 1):
        print(f"  Multi-wallet {i}:")
        print(f"    BTC: {wallet['btc']['addresses']['legacy']}")
        print(f"    ETH: {wallet['eth']['address']}")
        print(f"    TRX: {wallet['trx']['address']}")
    print()


def example_error_handling():
    """Example: Error handling and validation."""
    print("⚠️  Error Handling")
    print("=" * 50)

    # Test invalid private key
    try:
        invalid_crypto = Crypto("invalid_key", "btc")
    except ValueError as e:
        print(f"Invalid private key handled: {e}")

    # Test invalid coin type
    try:
        key = gen_key()
        invalid_coin = Crypto(key, "invalid_coin")
    except ValueError as e:
        print(f"Invalid coin type handled: {e}")

    # Test 0x prefix handling
    key = gen_key()
    key_with_prefix = "0x" + key
    btc_crypto = Crypto(key_with_prefix, "btc")
    print(f"0x prefix automatically removed: {len(btc_crypto.private_key) == 64}")

    # Test invalid address validation
    invalid_addresses = ["", "invalid", "1234567890"]
    print(f"\nInvalid address validation:")
    for addr in invalid_addresses:
        result = check_addr(addr)
        print(f"  '{addr}' → Valid: {result.valid}")

    print()


def example_dataclass_features():
    """Example: DataClass features and conversion."""
    print("📊 DataClass Features")
    print("=" * 50)

    key = gen_key()
    wallet = btc_wallet(key)

    print("WalletInfo dataclass:")
    print(f"  Type: {type(wallet)}")
    print(f"  Private Key: {wallet.private_key}")
    print(f"  Network: {wallet.network}")
    print(f"  Compressed: {wallet.compressed}")
    print(f"  Legacy Address: {wallet.addresses.legacy}")
    print()

    # Convert to dictionary
    wallet_dict = wallet.to_dict()
    print("Converted to dictionary:")
    for key, value in wallet_dict.items():
        print(f"  {key}: {value}")
    print()

    # ValidationResult dataclass
    result = check_addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    print("ValidationResult dataclass:")
    print(f"  Type: {type(result)}")
    print(f"  Valid: {result.valid}")
    print(f"  Coin: {result.coin}")
    print(f"  Dict: {result.to_dict()}")
    print()


def main():
    """Run all examples."""
    print("🚀 Libit Multi-Cryptocurrency Library Examples")
    print("=" * 80)
    print()

    examples = [
        example_key_generation,
        example_individual_wallets,
        example_ultra_short_names,
        example_multi_wallet,
        example_crypto_class,
        example_address_validation,
        example_validation_short_methods,
        example_bulk_generation,
        example_error_handling,
        example_dataclass_features,
    ]

    for example_func in examples:
        try:
            example_func()
        except Exception as e:
            print(f"❌ Error in {example_func.__name__}: {e}")
        print()

    print("✅ All examples completed!")
    print()
    print("📚 Quick Reference:")
    print("  Key Generation:    gen_key()")
    print("  Single Wallets:    btc(), ltc(), doge(), eth(), trx()")
    print("  Multi Wallet:      multi_wallet()")
    print("  Validation:        valid(), check(), coin_type()")
    print("  Bulk Generation:   gen_wallets(), gen_multi_wallets()")


if __name__ == "__main__":
    main()
