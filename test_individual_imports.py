#!/usr/bin/env python3
"""
Test individual imports to identify missing functions.
"""


def test_import(module_name, function_name):
    try:
        exec(f"from libit.{module_name} import {function_name}")
        return True
    except ImportError:
        return False


# Test lib module functions
lib_functions = [
    "bytes_addr",
    "bytes_eth",
    "bytes_trx",
    "bytes_wif",
    "dec_eth",
    "dec_trx",
    "dec_addr",
    "eth_addr",
    "hex_bytes",
    "passphrase_addr",
    "privatekey_addr",
    "privatekey_decimal",
    "privatekey_wif",
    "trx_addr",
    "wif_addr",
    "Ethereum",
    "tron",
]

print("Testing lib module functions:")
for func in lib_functions:
    result = test_import("lib", func)
    print(f"  {func}: {'✅' if result else '❌'}")

# Test wallet module functions
wallet_functions = [
    "WalletGenerator",
    "BulkWalletGenerator",
    "generate_private_key",
    "generate_bitcoin_wallet",
    "generate_ethereum_wallet",
    "generate_tron_wallet",
    "generate_multi_wallet",
    "from_private_key",
]

print("\nTesting wallet module functions:")
for func in wallet_functions:
    result = test_import("wallet", func)
    print(f"  {func}: {'✅' if result else '❌'}")

# Test utils module functions
utils_functions = [
    "is_valid_private_key",
    "is_valid_bitcoin_address",
    "is_valid_ethereum_address",
    "is_valid_tron_address",
    "format_private_key",
    "entropy_to_private_key",
    "AddressValidator",
]

print("\nTesting utils module functions:")
for func in utils_functions:
    result = test_import("utils", func)
    print(f"  {func}: {'✅' if result else '❌'}")

# Test validate module functions
validate_functions = [
    "Validator",
    "ValidationResult",
    "check_addr",
    "is_valid",
    "get_coin_type",
    "validate_multiple",
    "valid",
    "coin_type",
    "check",
]

print("\nTesting validate module functions:")
for func in validate_functions:
    result = test_import("validate", func)
    print(f"  {func}: {'✅' if result else '❌'}")
