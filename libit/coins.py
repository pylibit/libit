"""
Multi-cryptocurrency wallet generation module.
Supports Bitcoin, Ethereum, Tron, Litecoin, Dogecoin, Bitcoin Cash, and Dash.
Uses dataclasses for professional structure and error prevention.
"""

from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional, List, Union
import hashlib
import ecdsa
import secrets
from .bs58 import b58encode_check
from .bitcoin import hash160
from .lib import Ethereum, tron


@dataclass
class CoinConfig:
    """Configuration for different cryptocurrencies."""

    name: str
    symbol: str
    p2pkh_prefix: bytes
    p2sh_prefix: bytes
    wif_prefix: bytes
    bech32_hrp: Optional[str] = None


# Cryptocurrency configurations
COINS = {
    "btc": CoinConfig("Bitcoin", "BTC", b"\x00", b"\x05", b"\x80", "bc"),
    "ltc": CoinConfig("Litecoin", "LTC", b"\x30", b"\x32", b"\xb0", "ltc"),
    "doge": CoinConfig("Dogecoin", "DOGE", b"\x1e", b"\x16", b"\x9e"),
    "bch": CoinConfig("Bitcoin Cash", "BCH", b"\x00", b"\x05", b"\x80"),
    "dash": CoinConfig("Dash", "DASH", b"\x4c", b"\x10", b"\xcc"),
    "zcash": CoinConfig("Zcash", "ZEC", b"\x1c\xb8", b"\x1c\xbd", b"\x80"),
    "vtc": CoinConfig("Vertcoin", "VTC", b"\x47", b"\x05", b"\x80", "vtc"),
}


@dataclass
class AddressSet:
    """Standard address set for cryptocurrencies."""

    legacy: str
    script: str
    segwit: Optional[str] = None


@dataclass
class WalletInfo:
    """Complete wallet information with professional structure."""

    private_key: str
    wif: str
    decimal: int
    addresses: AddressSet
    network: str
    compressed: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for backward compatibility."""
        return asdict(self)

    network: str
    compressed: bool = True


class Crypto:
    """Universal cryptocurrency wallet generator with enhanced error handling."""

    def __init__(self, private_key: str, coin_type: str = "btc"):
        """
        Initialize crypto wallet with validation.

        Args:
            private_key: 64-character hex private key
            coin_type: Cryptocurrency type (btc, ltc, doge, bch, dash, zcash, vtc)

        Raises:
            ValueError: If private key format is invalid or coin type unsupported
        """
        if not isinstance(private_key, str):
            raise ValueError("Private key must be a string")

        # Remove 0x prefix if present
        if private_key.startswith("0x"):
            private_key = private_key[2:]

        if len(private_key) != 64:
            raise ValueError("Private key must be 64 hex characters")

        try:
            int(private_key, 16)
        except ValueError:
            raise ValueError("Private key must be valid hexadecimal")

        if coin_type not in COINS:
            raise ValueError(
                f"Unsupported coin: {coin_type}. Supported: {list(COINS.keys())}"
            )

        self.private_key = private_key
        self.coin = COINS[coin_type]
        self.coin_type = coin_type
        self._private_key_bytes = bytes.fromhex(private_key)
        self._public_key = None
        self._public_key_uncompressed = None

    def _get_public_key(self, compressed: bool = True) -> bytes:
        """Get public key from private key with caching."""
        cache_key = "_public_key" if compressed else "_public_key_uncompressed"

        if getattr(self, cache_key, None) is None:
            try:
                sk = ecdsa.SigningKey.from_string(
                    self._private_key_bytes, curve=ecdsa.SECP256k1
                )
                vk = sk.get_verifying_key()

                if compressed:
                    prefix = b"\x02" if vk.pubkey.point.y() % 2 == 0 else b"\x03"
                    public_key = prefix + vk.to_string()[:32]
                else:
                    public_key = b"\x04" + vk.to_string()

                setattr(self, cache_key, public_key)
            except Exception as e:
                raise ValueError(f"Failed to derive public key: {e}")

        return getattr(self, cache_key)

    def legacy(self, compressed: bool = True) -> str:
        """Get legacy P2PKH address (short name)."""
        return self.get_legacy_addr(compressed)

    def script(self, compressed: bool = True) -> str:
        """Get P2SH script address (short name)."""
        return self.get_script_addr(compressed)

    def get_legacy_addr(self, compressed: bool = True) -> str:
        """Get legacy P2PKH address."""
        try:
            public_key = self._get_public_key(compressed)
            hash160_result = hash160(public_key)
            versioned = self.coin.p2pkh_prefix + hash160_result
            return b58encode_check(versioned).decode("utf-8")
        except Exception as e:
            raise ValueError(f"Failed to generate legacy address: {e}")

    def get_script_addr(self, compressed: bool = True) -> str:
        """Get P2SH script address."""
        try:
            public_key = self._get_public_key(compressed)
            script = b"\x76\xa9\x14" + hash160(public_key) + b"\x88\xac"
            script_hash = hash160(script)
            versioned = self.coin.p2sh_prefix + script_hash
            return b58encode_check(versioned).decode("utf-8")
        except Exception as e:
            raise ValueError(f"Failed to generate script address: {e}")

    def wif(self, compressed: bool = True) -> str:
        """Get WIF format (short name)."""
        return self.get_wif(compressed)

    def decimal(self) -> int:
        """Get private key as decimal (short name)."""
        return self.get_decimal()

    def get_wif(self, compressed: bool = True) -> str:
        """Get WIF format."""
        try:
            if compressed:
                extended = self.coin.wif_prefix + self._private_key_bytes + b"\x01"
            else:
                extended = self.coin.wif_prefix + self._private_key_bytes
            return b58encode_check(extended).decode("utf-8")
        except Exception as e:
            raise ValueError(f"Failed to generate WIF: {e}")

    def get_decimal(self) -> int:
        """Get private key as decimal."""
        return int(self.private_key, 16)

    def addrs(self, compressed: bool = True) -> AddressSet:
        """Get all address types (short name)."""
        return self.get_addresses(compressed)

    def get_addresses(self, compressed: bool = True) -> AddressSet:
        """Get all address types."""
        return AddressSet(
            legacy=self.get_legacy_addr(compressed),
            script=self.get_script_addr(compressed),
            segwit=None,  # Not all coins support SegWit
        )

    def info(self, compressed: bool = True) -> WalletInfo:
        """Get complete wallet information (short name)."""
        return self.get_wallet_info(compressed)

    def get_wallet_info(self, compressed: bool = True) -> WalletInfo:
        """Get complete wallet information."""
        return WalletInfo(
            private_key=self.private_key,
            wif=self.get_wif(compressed),
            decimal=self.get_decimal(),
            addresses=self.get_addresses(compressed),
            network=self.coin.name,
            compressed=compressed,
        )


class MultiWallet:
    """Multi-cryptocurrency wallet manager with enhanced features."""

    def __init__(self, private_key: Optional[str] = None):
        """
        Initialize with single private key for all networks.

        Args:
            private_key: Hex private key. If None, generates new one.
        """
        if private_key is None:
            private_key = gen_key()

        # Validate private key
        if private_key.startswith("0x"):
            private_key = private_key[2:]

        if len(private_key) != 64:
            raise ValueError("Private key must be 64 hex characters")

        try:
            int(private_key, 16)
        except ValueError:
            raise ValueError("Private key must be valid hexadecimal")

        self.private_key = private_key
        self._wallets = {}
        self._eth_wallet = None
        self._trx_wallet = None

    def btc(self, compressed: bool = True) -> WalletInfo:
        """Get Bitcoin wallet."""
        if "btc" not in self._wallets:
            self._wallets["btc"] = Crypto(self.private_key, "btc")
        return self._wallets["btc"].get_wallet_info(compressed)

    def ltc(self, compressed: bool = True) -> WalletInfo:
        """Get Litecoin wallet."""
        if "ltc" not in self._wallets:
            self._wallets["ltc"] = Crypto(self.private_key, "ltc")
        return self._wallets["ltc"].get_wallet_info(compressed)

    def doge(self, compressed: bool = True) -> WalletInfo:
        """Get Dogecoin wallet."""
        if "doge" not in self._wallets:
            self._wallets["doge"] = Crypto(self.private_key, "doge")
        return self._wallets["doge"].get_wallet_info(compressed)

    def bch(self, compressed: bool = True) -> WalletInfo:
        """Get Bitcoin Cash wallet."""
        if "bch" not in self._wallets:
            self._wallets["bch"] = Crypto(self.private_key, "bch")
        return self._wallets["bch"].get_wallet_info(compressed)

    def dash(self, compressed: bool = True) -> WalletInfo:
        """Get Dash wallet."""
        if "dash" not in self._wallets:
            self._wallets["dash"] = Crypto(self.private_key, "dash")
        return self._wallets["dash"].get_wallet_info(compressed)

    def zcash(self, compressed: bool = True) -> WalletInfo:
        """Get Zcash wallet."""
        if "zcash" not in self._wallets:
            self._wallets["zcash"] = Crypto(self.private_key, "zcash")
        return self._wallets["zcash"].get_wallet_info(compressed)

    def vtc(self, compressed: bool = True) -> WalletInfo:
        """Get Vertcoin wallet."""
        if "vtc" not in self._wallets:
            self._wallets["vtc"] = Crypto(self.private_key, "vtc")
        return self._wallets["vtc"].get_wallet_info(compressed)

    def eth(self) -> Dict[str, Any]:
        """Get Ethereum wallet."""
        if self._eth_wallet is None:
            try:
                self._eth_wallet = Ethereum(self.private_key)
            except Exception as e:
                raise ValueError(f"Failed to create Ethereum wallet: {e}")

        return {
            "private_key": self.private_key,
            "decimal": self._eth_wallet.get_decimal(),
            "address": self._eth_wallet.get_address(),
            "network": "Ethereum",
        }

    def trx(self) -> Dict[str, Any]:
        """Get Tron wallet."""
        if self._trx_wallet is None:
            try:
                self._trx_wallet = tron(self.private_key)
            except Exception as e:
                raise ValueError(f"Failed to create Tron wallet: {e}")

        return {
            "private_key": self.private_key,
            "decimal": self._trx_wallet.get_decimal(),
            "address": self._trx_wallet.get_address(),
            "hex_address": self._trx_wallet.get_hexAddress(),
            "evm_address": self._trx_wallet.get_evmAddress(),
            "network": "Tron",
        }

    def all_coins(self, compressed: bool = True) -> Dict[str, Any]:
        """Get wallets for all supported cryptocurrencies."""
        return {
            "btc": asdict(self.btc(compressed)),
            "ltc": asdict(self.ltc(compressed)),
            "doge": asdict(self.doge(compressed)),
            "bch": asdict(self.bch(compressed)),
            "dash": asdict(self.dash(compressed)),
            "zcash": asdict(self.zcash(compressed)),
            "vtc": asdict(self.vtc(compressed)),
            "eth": self.eth(),
            "trx": self.trx(),
        }

    def all(self, compressed: bool = True) -> Dict[str, Any]:
        """Get all wallets (short name)."""
        return self.all_coins(compressed)


# Convenience functions with shorter names
def gen_key() -> str:
    """Generate secure 256-bit private key."""
    return secrets.randbits(256).to_bytes(32, "big").hex()


def multi_wallet(private_key: Optional[str] = None) -> MultiWallet:
    """Create multi-cryptocurrency wallet."""
    return MultiWallet(private_key)


def btc_wallet(
    private_key: Optional[str] = None, compressed: bool = True
) -> WalletInfo:
    """Generate Bitcoin wallet."""
    if private_key is None:
        private_key = gen_key()
    return Crypto(private_key, "btc").get_wallet_info(compressed)


def ltc_wallet(
    private_key: Optional[str] = None, compressed: bool = True
) -> WalletInfo:
    """Generate Litecoin wallet."""
    if private_key is None:
        private_key = gen_key()
    return Crypto(private_key, "ltc").get_wallet_info(compressed)


def doge_wallet(
    private_key: Optional[str] = None, compressed: bool = True
) -> WalletInfo:
    """Generate Dogecoin wallet."""
    if private_key is None:
        private_key = gen_key()
    return Crypto(private_key, "doge").get_wallet_info(compressed)


def bch_wallet(
    private_key: Optional[str] = None, compressed: bool = True
) -> WalletInfo:
    """Generate Bitcoin Cash wallet."""
    if private_key is None:
        private_key = gen_key()
    return Crypto(private_key, "bch").get_wallet_info(compressed)


def dash_wallet(
    private_key: Optional[str] = None, compressed: bool = True
) -> WalletInfo:
    """Generate Dash wallet."""
    if private_key is None:
        private_key = gen_key()
    return Crypto(private_key, "dash").get_wallet_info(compressed)


def zcash_wallet(
    private_key: Optional[str] = None, compressed: bool = True
) -> WalletInfo:
    """Generate Zcash wallet."""
    if private_key is None:
        private_key = gen_key()
    return Crypto(private_key, "zcash").get_wallet_info(compressed)


def vtc_wallet(
    private_key: Optional[str] = None, compressed: bool = True
) -> WalletInfo:
    """Generate Vertcoin wallet."""
    if private_key is None:
        private_key = gen_key()
    return Crypto(private_key, "vtc").get_wallet_info(compressed)


def eth_wallet(private_key: Optional[str] = None) -> Dict[str, Any]:
    """Generate Ethereum wallet."""
    if private_key is None:
        private_key = gen_key()
    try:
        eth = Ethereum(private_key)
        return {
            "private_key": private_key,
            "decimal": eth.get_decimal(),
            "address": eth.get_address(),
            "network": "Ethereum",
        }
    except Exception as e:
        raise ValueError(f"Failed to create Ethereum wallet: {e}")


def trx_wallet(private_key: Optional[str] = None) -> Dict[str, Any]:
    """Generate Tron wallet."""
    if private_key is None:
        private_key = gen_key()
    try:
        trx = tron(private_key)
        return {
            "private_key": private_key,
            "decimal": trx.get_decimal(),
            "address": trx.get_address(),
            "hex_address": trx.get_hexAddress(),
            "evm_address": trx.get_evmAddress(),
            "network": "Tron",
        }
    except Exception as e:
        raise ValueError(f"Failed to create Tron wallet: {e}")


# Bulk generation functions with enhanced error handling
def gen_wallets(
    count: int, coin_type: str = "btc", compressed: bool = True
) -> List[WalletInfo]:
    """Generate multiple wallets for specified coin."""
    if count <= 0:
        raise ValueError("Count must be positive")
    if count > 10000:
        raise ValueError("Count too large (max 10000)")
    if coin_type not in COINS:
        raise ValueError(f"Unsupported coin: {coin_type}")

    wallets = []
    for _ in range(count):
        try:
            private_key = gen_key()
            wallet = Crypto(private_key, coin_type).get_wallet_info(compressed)
            wallets.append(wallet)
        except Exception as e:
            raise ValueError(f"Failed to generate wallet: {e}")
    return wallets


def gen_multi_wallets(count: int, compressed: bool = True) -> List[Dict[str, Any]]:
    """Generate multiple multi-coin wallets."""
    if count <= 0:
        raise ValueError("Count must be positive")
    if count > 1000:
        raise ValueError("Count too large for multi-wallets (max 1000)")

    wallets = []
    for _ in range(count):
        try:
            private_key = gen_key()
            multi = MultiWallet(private_key)
            wallets.append(multi.all_coins(compressed))
        except Exception as e:
            raise ValueError(f"Failed to generate multi-wallet: {e}")
    return wallets


# Short aliases
btc = btc_wallet
ltc = ltc_wallet
doge = doge_wallet
bch = bch_wallet
dash = dash_wallet
zcash = zcash_wallet
vtc = vtc_wallet
eth = eth_wallet
trx = trx_wallet
