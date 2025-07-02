
# Libit - Professional Cryptocurrency Wallet Library

[![Read the Docs](https://img.shields.io/readthedocs/libit)](https://libit.readthedocs.io 'libit documentation') [![GitHub commit check runs](https://img.shields.io/github/check-runs/pylibit/libit/main)](https://github.com/pylibit/libit)  [![GitHub last commit](https://img.shields.io/github/last-commit/pylibit/libit)](https://github.com/pylibit/libit)  [![GitHub commit activity](https://img.shields.io/github/commit-activity/m/pylibit/libit)](https://github.com/pylibit/libit)  [![GitHub top language](https://img.shields.io/github/languages/top/pylibit/libit)](https://github.com/pylibit/libit)  [![PyPI - Downloads](https://img.shields.io/pypi/dm/libit)](https://pypi.org/project/libit/)  [![Website](https://img.shields.io/website?url=https%3A%2F%2Flibit.readthedocs.io&up_color=blue&style=plastic)](https://libit.readthedocs.io)

A professional, fast and comprehensive Python library for cryptocurrency wallet generation and management. Supports Bitcoin (with all address formats), Ethereum, and Tron networks.

## Features

- **Bitcoin Address Generation**: `P2PKH`, `P2SH`, `P2WPKH`, `P2WSH` (Legacy, Script, SegWit v0)
- **Multiple Networks**: Bitcoin, Ethereum, Tron
- **Secure Key Generation**: Cryptographically secure random key generation
- **Address Validation**: Comprehensive validation for all supported address types
- **Bulk Operations**: Generate multiple wallets efficiently
- **Professional API**: Clean, intuitive interface with full type hints
- **Backward Compatibility**: Maintains compatibility with previous versions

## Installation

Install the library via pip:

```bash
pip install libit
# Mac and Linux: `pip3 install libit`
```

## Quick Start

### Generate a Bitcoin Wallet with All Address Types

generate a Bitcoin wallet that supports all address formats , including Legacy, Script, and SegWit:


```python
from libit import Bitcoin

# Create wallet from private key
wallet = Bitcoin("a1b2c3d4e5f6789...")

# Get all address formats
addresses = wallet.get_all_addresses()
print(addresses)
# {
#     'p2pkh': '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',    # Legacy (starts with 1)
#     'p2sh': '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy',     # Script (starts with 3)
#     'p2wpkh': 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',  # SegWit (starts with bc1)
#     'p2wsh': 'bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3'   # SegWit Script
# }

# Get complete wallet information
wallet_info = wallet.get_wallet_info()
print(wallet_info)
```

### Generate New Wallets

generate a new Bitcoin wallet with all address formats, or generate wallets for multiple networks (Bitcoin, Ethereum, Tron):

```python
from libit import generate_bitcoin_wallet, generate_multi_wallet

# Generate a new Bitcoin wallet
btc_wallet = generate_bitcoin_wallet()
print(f"Private Key: {btc_wallet['private_key']}")
print(f"P2PKH Address: {btc_wallet['addresses']['p2pkh']}")
print(f"SegWit Address: {btc_wallet['addresses']['p2wpkh']}")

# Generate wallets for all supported networks
multi_wallet = generate_multi_wallet()
print(f"Bitcoin: {multi_wallet['bitcoin']['addresses']['p2pkh']}")
print(f"Ethereum: {multi_wallet['ethereum']['address']}")
print(f"Tron: {multi_wallet['tron']['address']}")
```

### Address Validation

Address validation for Bitcoin, Ethereum, and Tron networks:


```python
from libit import AddressValidator

# Validate any cryptocurrency address
validator = AddressValidator()

# Bitcoin addresses
btc_result = validator.validate_bitcoin("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
print(btc_result)  # {'is_valid': True, 'type': 'P2PKH', 'network': 'bitcoin'}

# Auto-detect network and validate
result = validator.validate_any("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
print(result)  # {'is_valid': True, 'type': 'P2WPKH', 'network': 'bitcoin'}
```

### Bulk Wallet Generation

bulk wallet generation for Bitcoin and multi-network wallets, which allows you to create multiple wallets efficiently:

```python
from libit import BulkWalletGenerator

# Generate 100 Bitcoin wallets
wallets = BulkWalletGenerator.generate_bitcoin_wallets(100)

# Generate 50 multi-network wallets
multi_wallets = BulkWalletGenerator.generate_multi_wallets(50)
```

## Detailed Usage

In this section, we will cover the detailed usage of the library, including how to work with different address types, private keys, and networks.

### Bitcoin Address Types

The library supports all major Bitcoin address formats:

```python
from libit import Bitcoin

wallet = Bitcoin("private_key_here")

# Legacy P2PKH (Pay-to-Public-Key-Hash) - starts with '1'
p2pkh = wallet.get_p2pkh_address()

# Script P2SH (Pay-to-Script-Hash) - starts with '3'  
p2sh = wallet.get_p2sh_address()

# SegWit P2WPKH (Pay-to-Witness-Public-Key-Hash) - starts with 'bc1'
p2wpkh = wallet.get_p2wpkh_address()

# SegWit P2WSH (Pay-to-Witness-Script-Hash) - starts with 'bc1'
p2wsh = wallet.get_p2wsh_address()
```

### Working with Private Keys

You can generate, validate, and format private keys using the library's utilities:

```python
from libit import generate_private_key, is_valid_private_key, format_private_key

# Generate cryptographically secure private key
private_key = generate_private_key()

# Validate private key
if is_valid_private_key(private_key):
    print("Valid private key")

# Format private key (handles various input formats)
formatted = format_private_key("0x" + private_key)  # Removes 0x prefix
```

### Ethereum and Tron

You can generate, validate, and format private keys using the library's utilities, including support for Ethereum and Tron networks:

```python
from libit import Ethereum, Tron

# Ethereum wallet
eth = Ethereum("private_key_here")
eth_address = eth.get_address()

# Tron wallet  
trx = tron("private_key_here")
trx_address = trx.get_address()
evm_address = trx.get_evmAddress()  # EVM-compatible format
```

### Legacy Functions (Backward Compatibility)

All previous functions are still available for backward compatibility. You can use the legacy functions as before:


```python
from libit import privatekey_addr, bytes_addr, wif_addr

# These functions work exactly as before
address = privatekey_addr("private_key_hex")
address_from_bytes = bytes_addr(b"32_bytes_seed")
address_from_wif = wif_addr("WIF_string")
```

### Reuse Method

Extract Private Key and Public Key From Transaction ID (hash) for reuse type wallet:

```python
import libit
from libit import reuse

r = 0x0861cce1da15fc2dd79f1164c4f7b3e6c1526e7e8d85716578689ca9a5dc349d
s1 = 0x6cf26e2776f7c94cafcee05cc810471ddca16fa864d13d57bee1c06ce39a3188
s2 = 0x4ba75bdda43b3aab84b895cfd9ef13a477182657faaf286a7b0d25f0cb9a7de2
z1 = 0x01b125d18422cdfa7b153f5bcf5b01927cf59791d1d9810009c70cd37b14f4e6
z2 = 0x339ff7b1ced3a45c988b3e4e239ea745db3b2b3fda6208134691bd2e4a37d6e1

pvk, pub = reuse.extract_key(r, s1, s2, z1, z2)
# pvk: e773cf35fce567d0622203c28f67478a3361bae7e6eb4366b50e1d27eb1ed82e
# pub: eaa57720a5b012351d42b2d9ed6409af2b7cff11d2b8631684c1c97f49685fbb
# convert private key to bitcoin address
address = libit.privatekey_addr(pvk, True)
# output: 1FCpHq81nNLPkppTmidmoHAUy8xApTZ292
# (Total Transaction: 8 | Received: 1.56534788 BTC | Total Sent: 1.56534788 BTC)

```


## Security Features

- **Cryptographically Secure**: Uses `secrets` module for random number generation
- **Input Validation**: Comprehensive validation of all inputs
- **Error Handling**: Graceful error handling with informative messages
- **No External Dependencies**: Minimal dependencies for security

## API Reference

### Classes

- **`Bitcoin`**: Complete Bitcoin wallet functionality
- **`WalletGenerator`**: Generate wallets for multiple networks
- **`BulkWalletGenerator`**: Efficient bulk wallet generation
- **`AddressValidator`**: Validate addresses across all networks

### Address Types Supported

| Type | Description | Starts With | Example |
|------|-------------|-------------|---------|
| P2PKH | Legacy | `1` | `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa` |
| P2SH | Script | `3` | `3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy` |
| P2WPKH | SegWit v0 | `bc1` | `bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4` |
| P2WSH | SegWit v0 Script | `bc1` | `bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q...` |

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: [https://pylibit.github.io/libit/](https://pylibit.github.io/libit/)
- **Issues**: [GitHub Issues](https://github.com/pylibit/libit/issues)
- **Email**: Pymmdrza@gmail.com


