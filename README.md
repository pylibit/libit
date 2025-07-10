
# Libit - Professional Multi-Cryptocurrency Wallet Library

[![Read the Docs](https://img.shields.io/readthedocs/libit)](https://libit.readthedocs.io 'libit documentation') [![GitHub commit check runs](https://img.shields.io/github/check-runs/pylibit/libit/main)](https://github.com/pylibit/libit)  [![GitHub last commit](https://img.shields.io/github/last-commit/pylibit/libit)](https://github.com/pylibit/libit)  [![GitHub commit activity](https://img.shields.io/github/commit-activity/m/pylibit/libit)](https://github.com/pylibit/libit)  [![GitHub top language](https://img.shields.io/github/languages/top/pylibit/libit)](https://github.com/pylibit/libit)  [![PyPI - Downloads](https://img.shields.io/pypi/dm/libit)](https://pypi.org/project/libit/)  [![Website](https://img.shields.io/website?url=https%3A%2F%2Flibit.readthedocs.io&up_color=blue&style=plastic)](https://libit.readthedocs.io)

A professional, fast and comprehensive Python library for multi-cryptocurrency wallet generation and management. Supports **Bitcoin, Litecoin, Dogecoin, Bitcoin Cash, Dash, Ethereum, and Tron** networks with all address formats.

## Features

- **9 Cryptocurrencies**: Bitcoin, Litecoin, Dogecoin, Bitcoin Cash, Dash, Zcash, Vertcoin, Ethereum, Tron
- **All Address Types**: Legacy, Script, SegWit (where supported)  
- **Ultra-Short Function Names**: Minimal API like `btc()`, `eth()`, `valid()`, `check()`
- **Professional DataClasses**: Type-safe structure with comprehensive error handling
- **Enhanced Validation**: Auto-detect and validate all supported cryptocurrencies
- **Bulk Operations**: Generate multiple wallets efficiently
- **Secure Generation**: Cryptographically secure random key generation
- **Full Backward Compatibility**: All legacy functions still work

## Installation

```bash
pip install libit --upgrade
```

## Quick Start

### Multi-Cryptocurrency Wallet

```python
from libit import gen_key, multi_wallet

# Generate secure private key
private_key = gen_key()
# Create multi-crypto wallet
wallet = multi_wallet(private_key)
# Access different cryptocurrencies
btc = wallet.btc()      # Bitcoin
ltc = wallet.ltc()      # Litecoin  
doge = wallet.doge()    # Dogecoin
bch = wallet.bch()      # Bitcoin Cash
dash = wallet.dash()    # Dash
eth = wallet.eth()      # Ethereum
trx = wallet.trx()      # Tron

print(f"BTC Legacy: {btc.addresses.legacy}")
print(f"LTC Legacy: {ltc.addresses.legacy}")
print(f"ETH Address: {eth['address']}")
```

### Individual Coin Wallets

```python
from libit import btc_wallet, ltc_wallet, doge_wallet, eth_wallet

private_key = "your_private_key_here"
```
# Individual wallets with short function names
### Ultra-Short Function Names

Generate wallets with minimal code:

```python
from libit import btc, ltc, doge, bch, dash, zcash, vtc, eth, trx

# Auto-generate private keys and create wallets
btc_wallet = btc()
ltc_wallet = ltc()
doge_wallet = doge()
eth_wallet = eth()
trx_wallet = trx()

print(f"Bitcoin: {btc_wallet.addresses.legacy}")
print(f"Litecoin: {ltc_wallet.addresses.legacy}") 
print(f"Dogecoin: {doge_wallet.addresses.legacy}")
print(f"Ethereum: {eth_wallet['address']}")
print(f"Tron: {trx_wallet['address']}")
```

### Traditional Function Names

```python
from libit import gen_key, btc_wallet, ltc_wallet, doge_wallet, eth_wallet

# Generate with custom private key
private_key = gen_key()
btc = btc_wallet(private_key)
ltc = ltc_wallet(private_key)
doge = doge_wallet(private_key)
eth = eth_wallet(private_key)

print(f"Bitcoin: {btc.addresses.legacy}")
print(f"Litecoin: {ltc.addresses.legacy}")
print(f"Dogecoin: {doge.addresses.legacy}")
print(f"Ethereum: {eth['address']}")
```

### Address Validation

Enhanced validation with ultra-short function names:

```python
from libit import check_addr, is_valid, valid, coin_type, check

# Traditional validation
result = check_addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
print(f"Valid: {result.valid}")
print(f"Coin: {result.coin}")
print(f"Type: {result.addr_type}")

# Ultra-short validation
is_valid_addr = valid("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
detected_coin = coin_type("LdP8Qox1VAhCzLJNqrr74YovaWYyNBUWvL")
quick_check = check("DQE1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")

print(f"valid() → {is_valid_addr}")
print(f"coin_type() → {detected_coin}")  # ltc
print(f"check() → {quick_check.coin}")   # doge
```
### Bulk Wallet Generation

Generate multiple wallets efficiently:

```python
from libit import gen_wallets, gen_multi_wallets

# Generate 100 Bitcoin wallets
btc_wallets = gen_wallets(100, 'btc')
for wallet in btc_wallets[:3]:  # Show first 3
    print(f"BTC: {wallet.addresses.legacy}")

# Generate 50 Litecoin wallets  
ltc_wallets = gen_wallets(50, 'ltc')

# Generate multi-cryptocurrency wallets
multi_wallets = gen_multi_wallets(10)
for wallet in multi_wallets[:2]:  # Show first 2
    print(f"BTC: {wallet['btc']['addresses']['legacy']}")
    print(f"ETH: {wallet['eth']['address']}")
    print(f"ZEC: {wallet['zcash']['addresses']['legacy']}")
```

### Multi-Wallet Manager

Use one private key for all cryptocurrencies:

```python
from libit import multi_wallet, gen_key

# Create multi-wallet (auto-generates key)
multi = multi_wallet()

# Or use custom key
key = gen_key()
multi = multi_wallet(key)

# Access individual cryptocurrencies
btc_info = multi.btc()
ltc_info = multi.ltc()
eth_info = multi.eth()
zcash_info = multi.zcash()

# Get all supported cryptocurrencies
all_wallets = multi.all()
print(f"Generated wallets for {len(all_wallets)} cryptocurrencies")
```

## Supported Cryptocurrencies

| Coin | Symbol | Legacy | Script | SegWit | Short Function | Full Function |
|------|--------|--------|--------|--------|----------------|---------------|
| Bitcoin | BTC | ✅ (1...) | ✅ (3...) | ✅ (bc1...) | `btc()` | `btc_wallet()` |
| Litecoin | LTC | ✅ (L...) | ✅ (M...) | ✅ (ltc1...) | `ltc()` | `ltc_wallet()` |
| Dogecoin | DOGE | ✅ (D...) | ✅ (9...) | ❌ | `doge()` | `doge_wallet()` |
| Bitcoin Cash | BCH | ✅ (1...) | ✅ (3...) | ❌ | `bch()` | `bch_wallet()` |
| Dash | DASH | ✅ (X...) | ✅ (7...) | ❌ | `dash()` | `dash_wallet()` |
| Zcash | ZEC | ✅ (t1...) | ✅ (t3...) | ❌ | `zcash()` | `zcash_wallet()` |
| Vertcoin | VTC | ✅ (V...) | ✅ (3...) | ✅ (vtc1...) | `vtc()` | `vtc_wallet()` |
| Ethereum | ETH | ✅ (0x...) | ❌ | ❌ | `eth()` | `eth_wallet()` |
| Tron | TRX | ✅ (T...) | ❌ | ❌ | `trx()` | `trx_wallet()` |


## Quick API Reference

### Ultra-Short Functions

```python
from libit import btc, ltc, doge, eth, trx, valid, check, coin_type

# Generate wallets (auto-generates private keys)
btc_wallet = btc()
eth_wallet = eth()

# Validation
is_valid = valid("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
coin = coin_type("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4") 
result = check("LdP8Qox1VAhCzLJNqrr74YovaWYyNBUWvL")
```

### Professional DataClasses


The library uses Python dataclasses for better structure and type safety. Each wallet function returns a structured `WalletInfo` dataclass, and validation functions return a `ValidationResult` dataclass.

```python
from libit import WalletInfo, ValidationResult, AddressSet

# All wallet functions return structured dataclasses
wallet = btc()  # Returns WalletInfo dataclass
print(wallet.addresses.legacy)  # Type-safe access
print(wallet.to_dict())  # Convert to dictionary

# Validation returns structured results
result = check("address")  # Returns ValidationResult dataclass
print(result.valid, result.coin, result.addr_type)
```
## Bulk Generation

### Bulk Generation

Generate multiple wallets efficiently:

```python
from libit import gen_wallets, gen_multi_wallets

# Generate 100 Bitcoin wallets
btc_wallets = gen_wallets(100, 'btc')

# Generate 50 Litecoin wallets
ltc_wallets = gen_wallets(50, 'ltc')

# Generate 10 multi-cryptocurrency wallets
multi_wallets = gen_multi_wallets(10)
```

## Advanced Usage

Advanced usage includes complete multi-wallet access and professional data structure:


### Complete Multi-Wallet Access

Create a multi-wallet that supports all cryptocurrencies with a single private key:

```python
from libit import multi_wallet

wallet = multi_wallet("your_private_key_here")

# Get all cryptocurrencies at once
all_coins = wallet.all_coins()

# Access specific coins
btc_info = wallet.btc()
print(f"BTC WIF: {btc_info.wif}")
print(f"BTC Decimal: {btc_info.decimal}")
print(f"Legacy: {btc_info.addresses.legacy}")
print(f"Script: {btc_info.addresses.script}")
```

### DataClass Benefits

The library uses Python dataclasses for better structure:

```python
from libit import btc_wallet

wallet = btc_wallet("private_key_here")

# Professional data structure
print(f"Network: {wallet.network}")
print(f"Compressed: {wallet.compressed}")
print(f"WIF: {wallet.wif}")

# Type-safe address access
addresses = wallet.addresses
print(f"Legacy: {addresses.legacy}")
print(f"Script: {addresses.script}")
```

## Backward Compatibility

All legacy functions continue to work:

```python
# Legacy Bitcoin class (still supported)
from libit import Bitcoin
wallet = Bitcoin("private_key")
addresses = wallet.get_all_addresses()

# Legacy functions (still supported)
from libit import privatekey_addr, generate_bitcoin_wallet
addr = privatekey_addr("private_key")
new_wallet = generate_bitcoin_wallet()

# Legacy Ethereum & Tron (still supported)
from libit import Ethereum, tron
eth = Ethereum("private_key")
trx = tron("private_key")
```

## Security Features

- **Cryptographically Secure**: Uses `secrets` module for random number generation
- **Input Validation**: Comprehensive validation of all inputs with proper error handling
- **DataClass Safety**: Type-safe data structures prevent runtime errors
- **No External Dependencies**: Minimal dependencies for maximum security
- **Professional Error Handling**: Graceful error handling with informative messages

## Testing

Run the test suite:

```bash
python -m pytest tests_enhanced.py -v
```

Or test basic functionality:

```bash
python examples_enhanced.py
```

## API Reference

### Core Functions

- `gen_key()` - Generate secure private key
- `multi_wallet(key)` - Create multi-cryptocurrency wallet
- `btc_wallet(key)` - Bitcoin wallet
- `ltc_wallet(key)` - Litecoin wallet  
- `doge_wallet(key)` - Dogecoin wallet
- `bch_wallet(key)` - Bitcoin Cash wallet
- `dash_wallet(key)` - Dash wallet
- `eth_wallet(key)` - Ethereum wallet
- `trx_wallet(key)` - Tron wallet

### Validation Functions

- `check_addr(address)` - Comprehensive address validation
- `is_valid(address)` - Quick validation check
- `get_coin_type(address)` - Auto-detect cryptocurrency
- `validate_multiple(addresses)` - Bulk validation

### Bulk Generation

- `gen_wallets(count, coin_type)` - Generate multiple wallets for specific coin
- `gen_multi_wallets(count)` - Generate multiple multi-crypto wallets

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License.

## Support

- **Documentation**: [https://pylibit.github.io/libit/](https://pylibit.github.io/libit/)
- **Issues**: [GitHub Issues](https://github.com/pylibit/libit/issues)  
- **Email**: Pymmdrza@gmail.com

---

**⚠️ Disclaimer**: This library is for educational and development purposes. Always ensure proper security practices when handling private keys and cryptocurrency assets in production environments.


