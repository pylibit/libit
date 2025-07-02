"""
Example usage of the libit library with all Bitcoin address formats.
"""

from libit import (
    Bitcoin,
    generate_bitcoin_wallet,
    generate_multi_wallet,
    private_key_to_all_addresses,
    AddressValidator,
    WalletGenerator,
    BulkWalletGenerator,
)


def main():
    print("=== Libit Bitcoin Wallet Library Examples ===\n")

    # Example 1: Generate a new Bitcoin wallet
    print("1. Generate New Bitcoin Wallet:")
    print("-" * 40)
    new_wallet = generate_bitcoin_wallet(compressed=True)
    print(f"Private Key: {new_wallet['private_key']}")
    print(f"WIF: {new_wallet['wif']}")
    print("Addresses:")
    for addr_type, address in new_wallet["addresses"].items():
        print(f"  {addr_type.upper()}: {address}")
    print()

    # Example 2: Create wallet from existing private key
    print("2. Create Wallet from Private Key:")
    print("-" * 40)
    private_key = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
    wallet = Bitcoin(private_key)

    print(f"Private Key: {wallet.get_private_key()}")
    print(f"Decimal: {wallet.get_decimal()}")
    print("All Address Types:")
    addresses = wallet.get_all_addresses(compressed=True)
    for addr_type, address in addresses.items():
        print(f"  {addr_type.upper()}: {address}")
    print()

    # Example 3: Individual address generation
    print("3. Individual Address Generation:")
    print("-" * 40)
    print(f"P2PKH (Legacy): {wallet.get_p2pkh_address()}")
    print(f"P2SH (Script): {wallet.get_p2sh_address()}")
    print(f"P2WPKH (SegWit): {wallet.get_p2wpkh_address()}")
    print(f"P2WSH (SegWit Script): {wallet.get_p2wsh_address()}")
    print()

    # Example 4: Multi-network wallet generation
    print("4. Multi-Network Wallet Generation:")
    print("-" * 40)
    multi_wallet = generate_multi_wallet()
    print("Bitcoin Addresses:")
    for addr_type, address in multi_wallet["bitcoin"]["addresses"].items():
        print(f"  {addr_type.upper()}: {address}")
    print(f"Ethereum: {multi_wallet['ethereum']['address']}")
    print(f"Tron: {multi_wallet['tron']['address']}")
    print()

    # Example 5: Address validation
    print("5. Address Validation:")
    print("-" * 40)
    validator = AddressValidator()

    test_addresses = [
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",  # P2PKH
        "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",  # P2SH
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",  # P2WPKH
        "0x742d35cc6500000000000000000000000000000000000000",  # Ethereum
        "TRX9J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",  # Tron (example)
    ]

    for addr in test_addresses:
        result = validator.validate_any(addr)
        print(f"Address: {addr[:20]}...")
        print(f"  Valid: {result['is_valid']}")
        print(f"  Type: {result['type']}")
        print(f"  Network: {result['network']}")
        print()

    # Example 6: Bulk wallet generation
    print("6. Bulk Wallet Generation:")
    print("-" * 40)
    bulk_wallets = BulkWalletGenerator.generate_bitcoin_wallets(5)
    for i, wallet_data in enumerate(bulk_wallets, 1):
        print(f"Wallet {i}:")
        print(f"  Private Key: {wallet_data['private_key'][:16]}...")
        print(f"  P2PKH: {wallet_data['addresses']['p2pkh']}")
        print(f"  P2WPKH: {wallet_data['addresses']['p2wpkh']}")
        print()

    # Example 7: Convenience functions
    print("7. Convenience Functions:")
    print("-" * 40)
    test_key = "c1b2c3d4e5f6c1b2c3d4e5f6c1b2c3d4e5f6c1b2c3d4e5f6c1b2c3d4e5f6c1b2"
    all_addresses = private_key_to_all_addresses(test_key)
    print("All addresses from convenience function:")
    for addr_type, address in all_addresses.items():
        print(f"  {addr_type.upper()}: {address}")


if __name__ == "__main__":
    main()
