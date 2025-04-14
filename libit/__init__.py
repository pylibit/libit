from .lib import (
    bytes_addr,
    bytes_eth,
    bytes_trx,
    bytes_wif,
    dec_eth,
    dec_trx,
    dec_addr,
    dec_trx,
    eth_addr,
    hex_bytes,
    passphrase_addr,
    privatekey_addr,
    privatekey_decimal,
    privatekey_wif,
    trx_addr,
    wif_addr,
    Ethereum,
    tron
)
from .Tron import Wallet
from .reuse import extract_key
from . import reuse

# tron address from private key hex format
tronAddress = Wallet.get_address
# tron address to hash string format
tronHash = Wallet.get_hashAddress
# tron address to hex string format (evm)
tronHex = Wallet.get_hexAddress
# private key to tron decimal format
tronDec = Wallet.get_decimal

__version__ = '1.6.9'
__all__ = [
    "bytes_addr",
    "bytes_eth",
    "bytes_trx",
    "bytes_wif",
    "dec_eth",
    "dec_trx",
    "dec_addr",
    "dec_trx",
    "eth_addr",
    "hex_bytes",
    "passphrase_addr",
    "privatekey_addr",
    "privatekey_decimal",
    "privatekey_wif",
    "trx_addr",
    "wif_addr",
    "Ethereum",
    # REUSED FUNCTIONS
    "extract_key",
    "reuse"
]
