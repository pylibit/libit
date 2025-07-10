"""
libit - Multi-cryptocurrency wallet generation and validation library
Supports Bitcoin, Ethereum, Tron, Litecoin, Dogecoin, Bitcoin Cash, Dash, Zcash, and Vertcoin.
"""

__version__ = "5.3.6"

# Core imports from lib (Legacy support)
from .lib import (
    bytes_addr,
    bytes_eth,
    bytes_trx,
    bytes_wif,
    dec_eth,
    dec_trx,
    dec_addr,
    eth_addr,
    hex_bytes,
    passphrase_addr,
    privatekey_addr,
    privatekey_decimal,
    privatekey_wif,
    trx_addr,
    wif_addr,
    Ethereum,
    tron,
)

# Bitcoin address generation
from .bitcoin import (
    Bitcoin,
    private_key_to_p2pkh,
    private_key_to_p2sh,
    private_key_to_p2wpkh,
    private_key_to_p2wsh,
    private_key_to_all_addresses,
    private_key_to_wallet_info,
)

# Multi-cryptocurrency support
from .coins import (
    Crypto,
    MultiWallet,
    CoinConfig,
    AddressSet,
    WalletInfo,
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
    gen_wallets,
    gen_multi_wallets,
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
)

# Enhanced validation
from .validate import (
    Validator,
    ValidationResult,
    check_addr,
    is_valid,
    get_coin_type,
    validate_multiple,
    # Ultra-short aliases
    valid,
    coin_type,
    check,
)

# Wallet generation utilities
from .wallet import (
    WalletGenerator,
    BulkWalletGenerator,
    generate_private_key,
    generate_bitcoin_wallet,
    generate_ethereum_wallet,
    generate_tron_wallet,
    generate_multi_wallet,
    from_private_key,
)

# Utility functions
from .utils import (
    is_valid_private_key,
    is_valid_bitcoin_address,
    is_valid_ethereum_address,
    is_valid_tron_address,
    format_private_key,
    entropy_to_private_key,
    AddressValidator,
)

# Legacy Tron support
from .Tron import Wallet
from .reuse import extract_key
from . import reuse

# Legacy aliases for backward compatibility
tronAddress = Wallet.get_address
tronHash = Wallet.get_hashAddress
tronHex = Wallet.get_hexAddress
tronDec = Wallet.get_decimal

# Define what gets exported
__all__ = [
    # Version
    "__version__",
    # Legacy functions
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
    "extract_key",
    "reuse",
    "Wallet",
    "tronAddress",
    "tronHash",
    "tronHex",
    "tronDec",
    # Bitcoin features
    "Bitcoin",
    "private_key_to_p2pkh",
    "private_key_to_p2sh",
    "private_key_to_p2wpkh",
    "private_key_to_p2wsh",
    "private_key_to_all_addresses",
    "private_key_to_wallet_info",
    # Multi-crypto (new & enhanced)
    "Crypto",
    "MultiWallet",
    "CoinConfig",
    "AddressSet",
    "WalletInfo",
    "gen_key",
    "multi_wallet",
    "btc_wallet",
    "ltc_wallet",
    "doge_wallet",
    "bch_wallet",
    "dash_wallet",
    "zcash_wallet",
    "vtc_wallet",
    "eth_wallet",
    "trx_wallet",
    "gen_wallets",
    "gen_multi_wallets",
    # Ultra-short aliases
    "btc",
    "ltc",
    "doge",
    "bch",
    "dash",
    "zcash",
    "vtc",
    "eth",
    "trx",
    # Validation (enhanced)
    "Validator",
    "ValidationResult",
    "check_addr",
    "is_valid",
    "get_coin_type",
    "validate_multiple",
    # Ultra-short validation aliases
    "valid",
    "coin_type",
    "check",
    # Wallet generation
    "WalletGenerator",
    "BulkWalletGenerator",
    "generate_private_key",
    "generate_bitcoin_wallet",
    "generate_ethereum_wallet",
    "generate_tron_wallet",
    "generate_multi_wallet",
    "from_private_key",
    # Utilities
    "is_valid_private_key",
    "is_valid_bitcoin_address",
    "is_valid_ethereum_address",
    "is_valid_tron_address",
    "format_private_key",
    "entropy_to_private_key",
    "AddressValidator",
]
