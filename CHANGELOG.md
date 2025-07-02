# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
