"""
Example usage of the enhanced libit library with multi-cryptocurrency support.
"""

from libit import (
    # New enhanced multi-crypto functions
    gen_key,
    multi_wallet,
    btc_wallet,
    ltc_wallet,
    doge_wallet,
    bch_wallet,
    dash_wallet,
    eth_wallet,
    trx_wallet,
    # Validation
    check_addr,
    is_valid,
    get_coin_type,
    # Legacy support
    Bitcoin,
    generate_bitcoin_wallet,
)


def main():
    print("=== Libit Enhanced Multi-Cryptocurrency Library ===\n")

    # Example 1: Generate private key and multi-wallet
    print("1. Generate Multi-Cryptocurrency Wallet:")
    print("-" * 50)
    private_key = gen_key()
    wallet = multi_wallet(private_key)

    print(f"Private Key: {private_key[:16]}...")
    print("\nAll Supported Cryptocurrencies:")

    # Bitcoin
    btc = wallet.btc()
    print(f"Bitcoin (BTC):")
    print(f"  Legacy:  {btc.addresses.legacy}")
    print(f"  Script:  {btc.addresses.script}")

    # Litecoin
    ltc = wallet.ltc()
    print(f"Litecoin (LTC):")
    print(f"  Legacy:  {ltc.addresses.legacy}")
    print(f"  Script:  {ltc.addresses.script}")

    # Dogecoin
    doge = wallet.doge()
    print(f"Dogecoin (DOGE):")
    print(f"  Legacy:  {doge.addresses.legacy}")
    print(f"  Script:  {doge.addresses.script}")

    # Bitcoin Cash
    bch = wallet.bch()
    print(f"Bitcoin Cash (BCH):")
    print(f"  Legacy:  {bch.addresses.legacy}")
    print(f"  Script:  {bch.addresses.script}")

    # Dash
    dash = wallet.dash()
    print(f"Dash (DASH):")
    print(f"  Legacy:  {dash.addresses.legacy}")
    print(f"  Script:  {dash.addresses.script}")

    # Ethereum
    eth = wallet.eth()
    print(f"Ethereum (ETH):")
    print(f"  Address: {eth['address']}")

    # Tron
    trx = wallet.trx()
    print(f"Tron (TRX):")
    print(f"  Address: {trx['address']}")
    print()

    # Example 2: Individual coin wallets
    print("2. Individual Coin Wallet Generation:")
    print("-" * 50)
    test_key = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

    # Short function names for each coin
    btc_info = btc_wallet(test_key)
    ltc_info = ltc_wallet(test_key)
    doge_info = doge_wallet(test_key)
    eth_info = eth_wallet(test_key)

    print(f"BTC Legacy:  {btc_info.addresses.legacy}")
    print(f"LTC Legacy:  {ltc_info.addresses.legacy}")
    print(f"DOGE Legacy: {doge_info.addresses.legacy}")
    print(f"ETH Address: {eth_info['address']}")
    print()

    # Example 3: Address validation
    print("3. Enhanced Address Validation:")
    print("-" * 50)

    test_addresses = [
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",  # Bitcoin P2PKH
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",  # Bitcoin SegWit
        "LdP8Qox1VAhCzLJNqrr74YovaWYyNBUWvL",  # Litecoin
        "DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L",  # Dogecoin
        "X9NxFVVTx7s6bqQV2WD8qL4tL7Y2WJ1fGh",  # Dash
        "0x742d35cc500000000000000000000000000000000000",  # Ethereum
        "TRX9J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",  # Tron (example)
    ]

    for addr in test_addresses[:4]:  # Test first 4 addresses
        result = check_addr(addr)
        coin = get_coin_type(addr)
        valid = is_valid(addr)

        print(f"Address: {addr[:25]}...")
        print(f"  Valid: {valid}")
        print(f"  Coin: {coin}")
        print(f"  Type: {result.addr_type}")
        print()

    # Example 4: Bulk generation
    print("4. Bulk Wallet Generation:")
    print("-" * 50)

    from libit import gen_wallets

    # Generate 3 Bitcoin wallets
    btc_wallets = gen_wallets(3, "btc")
    for i, wallet_info in enumerate(btc_wallets, 1):
        print(f"BTC Wallet {i}:")
        print(f"  Key: {wallet_info.private_key[:16]}...")
        print(f"  Legacy: {wallet_info.addresses.legacy}")
        print()

    # Example 5: Legacy Bitcoin class (still works)
    print("5. Legacy Bitcoin Class (Backward Compatibility):")
    print("-" * 50)
    legacy_btc = Bitcoin(test_key)
    addresses = legacy_btc.get_all_addresses()

    print("Legacy Bitcoin Class Output:")
    for addr_type, address in addresses.items():
        print(f"  {addr_type.upper()}: {address}")
    print()

    # Example 6: Quick functions
    print("6. Quick Utility Functions:")
    print("-" * 50)

    # Quick address validation
    quick_check = is_valid("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    print(f"Quick validation: {quick_check}")

    # Auto-detect coin type
    detected_coin = get_coin_type("LdP8Qox1VAhCzLJNqrr74YovaWYyNBUWvL")
    print(f"Detected coin: {detected_coin}")

    # Generate new key
    new_key = gen_key()
    print(f"New random key: {new_key[:16]}...")


if __name__ == "__main__":
    main()
