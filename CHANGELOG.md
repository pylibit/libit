# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [5.3.0] - 2025-07-02

### 🎉 Major Features Added

#### New Cryptocurrency Support
- **Zcash (ZEC)**: Complete support with Legacy (t1...) and Script (t3...) addresses
- **Vertcoin (VTC)**: Full support including Legacy (V...), Script (3...), and SegWit (vtc1...) addresses

#### Ultra-Short Function Names
- `btc()`, `ltc()`, `doge()`, `bch()`, `dash()`, `zcash()`, `vtc()` - Generate wallets with minimal code
- `eth()`, `trx()` - Ethereum and Tron wallet generation
- `valid()`, `check()`, `coin_type()` - Ultra-short validation functions
- All functions support auto-generation of private keys or custom key input

#### Enhanced DataClass Integration  
- Professional `WalletInfo` dataclass with `to_dict()` method
- Enhanced `ValidationResult` dataclass with `to_dict()` method
- Better error handling and type safety throughout the library
- Structured data access with intellisense support

#### Advanced Validation Features
- Auto-detection support for all 9 cryptocurrencies
- Enhanced validation for Zcash and Vertcoin addresses
- Ultra-short validation methods in `Validator` class: `btc()`, `ltc()`, `doge()`, etc.
- Comprehensive error handling for invalid inputs

### 🔧 Improvements

#### API Enhancements
- **Crypto Class**: Added short method names (`legacy()`, `script()`, `wif()`, `decimal()`, `addrs()`, `info()`)
- **MultiWallet Class**: Enhanced with better error handling and caching
- **Bulk Generation**: Improved with validation limits and error handling
- **Private Key Handling**: Automatic 0x prefix removal and validation

#### Performance & Reliability
- Better caching for public key generation
- Enhanced error messages with detailed context
- Input validation for all functions
- Comprehensive type hints and documentation

#### Developer Experience
- Ultra-short function aliases for rapid development
- Professional dataclass structure for type safety
- Better code organization and modularity
- Comprehensive examples and tests

### 🧪 Testing & Quality

#### Enhanced Test Suite
- New comprehensive test file `tests_multi_crypto.py`
- Tests for all 9 supported cryptocurrencies
- Validation testing for all address types
- Error handling and edge case testing
- DataClass functionality testing

#### Example Updates
- New `examples_multi_crypto.py` with comprehensive demonstrations
- Examples for all new features and cryptocurrencies
- Ultra-short function usage examples
- Professional dataclass usage examples

#### CI/CD Improvements
- Enhanced GitHub Actions with security scanning
- Type checking with mypy
- Code quality checks with bandit
- Comprehensive test coverage
- Multi-Python version testing (3.8-3.12)

### 📚 Documentation

#### Updated README
- Comprehensive documentation for all 9 cryptocurrencies
- Ultra-short function examples and usage
- Professional dataclass documentation
- Enhanced validation examples
- Quick API reference section

#### API Documentation
- Complete function documentation with examples
- DataClass structure documentation
- Error handling guidelines
- Best practices and usage patterns

### 🔄 Backward Compatibility

All previous functions and classes remain fully compatible:
- Legacy wallet generation functions
- Original validation functions  
- All Bitcoin, Ethereum, and Tron functionality
- Previous API signatures maintained

## [5.0.0] - 2025-07-02

### Added
- **Complete Bitcoin Address Support**: Added support for all major Bitcoin address formats
  - P2PKH (Pay-to-Public-Key-Hash) - Legacy addresses starting with '1'
  - P2SH (Pay-to-Script-Hash) - Script addresses starting with '3'  
  - P2WPKH (Pay-to-Witness-Public-Key-Hash) - SegWit addresses starting with 'bc1'
  - P2WSH (Pay-to-Witness-Script-Hash) - SegWit script addresses starting with 'bc1'
- **New Bitcoin Class**: Professional Bitcoin wallet class with comprehensive functionality
- **Wallet Generator**: Unified wallet generation for Bitcoin, Ethereum, and Tron
- **Address Validation**: Comprehensive validation for all supported address types
- **Bulk Operations**: Efficient bulk wallet generation capabilities
- **Utility Functions**: Enhanced cryptographic utilities and helpers
- **Type Hints**: Full type annotation support for better development experience
- **Professional API**: Clean, intuitive interface with consistent naming
- **Enhanced Security**: Cryptographically secure random key generation using `secrets` module

### Changed
- **Version Bump**: Updated to 5.0.0 to reflect major new features
- **Dependencies**: Updated minimum dependency versions for security
- **Documentation**: Completely rewritten README with comprehensive examples
- **Code Structure**: Organized code into logical modules (bitcoin.py, wallet.py, utils.py)

### Improved
- **Performance**: Optimized address generation algorithms
- **Security**: Enhanced input validation and error handling
- **Maintainability**: Refactored codebase with better organization
- **Testing**: Added comprehensive test suite
- **Examples**: Added detailed usage examples

### Backward Compatibility
- **Legacy Support**: All previous functions remain available and functional
- **Import Compatibility**: Existing imports continue to work without modification
- **API Stability**: No breaking changes to existing functionality

## [4.3.3] - Previous Release

### Features
- Basic Bitcoin address generation (P2PKH only)
- Ethereum address generation
- Tron address generation
- WIF (Wallet Import Format) support
- Basic cryptographic utilities

---

## Migration Guide

### Upgrading from 4.x to 5.x

The library maintains full backward compatibility. Your existing code will continue to work without any changes.

#### New Features Available

```python
# NEW: Bitcoin class with all address types
from libit import Bitcoin
wallet = Bitcoin("private_key_here")
addresses = wallet.get_all_addresses()

# NEW: Wallet generator
from libit import generate_bitcoin_wallet
wallet = generate_bitcoin_wallet()

# NEW: Address validation
from libit import AddressValidator
validator = AddressValidator()
result = validator.validate_any("address_here")

# OLD: Still works exactly the same
from libit import privatekey_addr
address = privatekey_addr("private_key_here")
```

### What's Next

- HD Wallet support (BIP32/BIP44)
- BIP39 mnemonic phrase support
- QR code generation
- Multi-signature support
- Testnet support
- Additional cryptocurrencies
