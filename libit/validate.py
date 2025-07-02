"""
Address validation utilities for multiple cryptocurrencies.
Enhanced with dataclasses and comprehensive error handling.
"""

from dataclasses import dataclass
from typing import Optional, Dict, Any, List
import hashlib
import re
from .bs58 import b58decode


@dataclass
class ValidationResult:
    """Address validation result with enhanced information."""

    address: str
    valid: bool
    coin: Optional[str] = None
    addr_type: Optional[str] = None
    network: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for backward compatibility."""
        return {
            "address": self.address,
            "is_valid": self.valid,
            "coin": self.coin,
            "type": self.addr_type,
            "network": self.network,
        }


class Validator:
    """Multi-cryptocurrency address validator with enhanced features."""

    # Address prefixes for different coins
    PREFIXES = {
        "btc": {"legacy": "1", "script": "3", "segwit": "bc1"},
        "ltc": {"legacy": "L", "script": "M", "segwit": "ltc1"},
        "doge": {"legacy": "D", "script": "9"},
        "bch": {"legacy": "1", "script": "3"},
        "dash": {"legacy": "X", "script": "7"},
        "zcash": {"legacy": "t1", "script": "t3"},
        "vtc": {"legacy": "V", "script": "3", "segwit": "vtc1"},
    }

    @staticmethod
    def _check_base58(address: str, expected_len: int = 25) -> bool:
        """Check Base58 address format and checksum with enhanced validation."""
        if not address or not isinstance(address, str):
            return False

        try:
            decoded = b58decode(address)
            if len(decoded) != expected_len:
                return False

            payload = decoded[:-4]
            checksum = decoded[-4:]
            calculated = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
            return checksum == calculated
        except Exception:
            return False

    @staticmethod
    def check_btc(address: str) -> ValidationResult:
        """Validate Bitcoin address."""
        if address.startswith("1"):
            valid = Validator._check_base58(address)
            return ValidationResult(address, valid, "btc", "legacy", "Bitcoin")
        elif address.startswith("3"):
            valid = Validator._check_base58(address)
            return ValidationResult(address, valid, "btc", "script", "Bitcoin")
        elif address.startswith("bc1"):
            valid = 14 <= len(address) <= 74
            addr_type = (
                "segwit_v0"
                if len(address) == 42
                else "segwit_script" if len(address) == 62 else "segwit"
            )
            return ValidationResult(address, valid, "btc", addr_type, "Bitcoin")

        return ValidationResult(address, False)

    @staticmethod
    def check_ltc(address: str) -> ValidationResult:
        """Validate Litecoin address."""
        if address.startswith("L"):
            valid = Validator._check_base58(address)
            return ValidationResult(address, valid, "ltc", "legacy", "Litecoin")
        elif address.startswith("M"):
            valid = Validator._check_base58(address)
            return ValidationResult(address, valid, "ltc", "script", "Litecoin")
        elif address.startswith("ltc1"):
            valid = 14 <= len(address) <= 74
            return ValidationResult(address, valid, "ltc", "segwit", "Litecoin")

        return ValidationResult(address, False)

    @staticmethod
    def check_doge(address: str) -> ValidationResult:
        """Validate Dogecoin address."""
        if address.startswith("D"):
            valid = Validator._check_base58(address)
            return ValidationResult(address, valid, "doge", "legacy", "Dogecoin")
        elif address.startswith("9"):
            valid = Validator._check_base58(address)
            return ValidationResult(address, valid, "doge", "script", "Dogecoin")

        return ValidationResult(address, False)

    @staticmethod
    def check_bch(address: str) -> ValidationResult:
        """Validate Bitcoin Cash address."""
        if address.startswith("1"):
            valid = Validator._check_base58(address)
            return ValidationResult(address, valid, "bch", "legacy", "Bitcoin Cash")
        elif address.startswith("3"):
            valid = Validator._check_base58(address)
            return ValidationResult(address, valid, "bch", "script", "Bitcoin Cash")

        return ValidationResult(address, False)

    @staticmethod
    def check_dash(address: str) -> ValidationResult:
        """Validate Dash address."""
        if address.startswith("X"):
            valid = Validator._check_base58(address)
            return ValidationResult(address, valid, "dash", "legacy", "Dash")
        elif address.startswith("7"):
            valid = Validator._check_base58(address)
            return ValidationResult(address, valid, "dash", "script", "Dash")

        return ValidationResult(address, False)

    @staticmethod
    def check_zcash(address: str) -> ValidationResult:
        """Validate Zcash address."""
        if address.startswith("t1"):
            valid = Validator._check_base58(address)
            return ValidationResult(address, valid, "zcash", "legacy", "Zcash")
        elif address.startswith("t3"):
            valid = Validator._check_base58(address)
            return ValidationResult(address, valid, "zcash", "script", "Zcash")

        return ValidationResult(address, False)

    @staticmethod
    def check_vtc(address: str) -> ValidationResult:
        """Validate Vertcoin address."""
        if address.startswith("V"):
            valid = Validator._check_base58(address)
            return ValidationResult(address, valid, "vtc", "legacy", "Vertcoin")
        elif address.startswith("3"):
            valid = Validator._check_base58(address)
            return ValidationResult(address, valid, "vtc", "script", "Vertcoin")
        elif address.startswith("vtc1"):
            valid = 14 <= len(address) <= 74
            return ValidationResult(address, valid, "vtc", "segwit", "Vertcoin")

        return ValidationResult(address, False)

    @staticmethod
    def check_eth(address: str) -> ValidationResult:
        """Validate Ethereum address."""
        if not address.startswith("0x") or len(address) != 42:
            return ValidationResult(address, False)

        try:
            int(address[2:], 16)
            return ValidationResult(address, True, "eth", "ethereum", "Ethereum")
        except ValueError:
            return ValidationResult(address, False)

    @staticmethod
    def check_trx(address: str) -> ValidationResult:
        """Validate Tron address."""
        if not address.startswith("T") or len(address) != 34:
            return ValidationResult(address, False)

        try:
            decoded = b58decode(address)
            if len(decoded) != 25 or decoded[0] != 0x41:
                return ValidationResult(address, False)

            payload = decoded[:-4]
            checksum = decoded[-4:]
            calculated = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
            valid = checksum == calculated
            return ValidationResult(address, valid, "trx", "tron", "Tron")
        except:
            return ValidationResult(address, False)

    @staticmethod
    def check_any(address: str) -> ValidationResult:
        """Auto-detect and validate any supported address."""
        if not address or not isinstance(address, str):
            return ValidationResult(address, False)

        # Try each coin type
        validators = [
            Validator.check_btc,
            Validator.check_ltc,
            Validator.check_doge,
            Validator.check_bch,
            Validator.check_dash,
            Validator.check_zcash,
            Validator.check_vtc,
            Validator.check_eth,
            Validator.check_trx,
        ]

        for validator in validators:
            try:
                result = validator(address)
                if result.valid:
                    return result
            except Exception:
                continue

        return ValidationResult(address, False)

    # Short method names
    @staticmethod
    def btc(address: str) -> ValidationResult:
        """Validate Bitcoin address (short name)."""
        return Validator.check_btc(address)

    @staticmethod
    def ltc(address: str) -> ValidationResult:
        """Validate Litecoin address (short name)."""
        return Validator.check_ltc(address)

    @staticmethod
    def doge(address: str) -> ValidationResult:
        """Validate Dogecoin address (short name)."""
        return Validator.check_doge(address)

    @staticmethod
    def bch(address: str) -> ValidationResult:
        """Validate Bitcoin Cash address (short name)."""
        return Validator.check_bch(address)

    @staticmethod
    def dash(address: str) -> ValidationResult:
        """Validate Dash address (short name)."""
        return Validator.check_dash(address)

    @staticmethod
    def zcash(address: str) -> ValidationResult:
        """Validate Zcash address (short name)."""
        return Validator.check_zcash(address)

    @staticmethod
    def vtc(address: str) -> ValidationResult:
        """Validate Vertcoin address (short name)."""
        return Validator.check_vtc(address)

    @staticmethod
    def eth(address: str) -> ValidationResult:
        """Validate Ethereum address (short name)."""
        return Validator.check_eth(address)

    @staticmethod
    def trx(address: str) -> ValidationResult:
        """Validate Tron address (short name)."""
        return Validator.check_trx(address)

    @staticmethod
    def auto(address: str) -> ValidationResult:
        """Auto-detect and validate address (short name)."""
        return Validator.check_any(address)


# Convenience functions with shorter names and enhanced error handling
def check_addr(address: str, coin: str = "auto") -> ValidationResult:
    """Check address for specific coin or auto-detect."""
    if not address or not isinstance(address, str):
        return ValidationResult(address, False)

    if coin == "auto":
        return Validator.check_any(address)

    validators = {
        "btc": Validator.check_btc,
        "ltc": Validator.check_ltc,
        "doge": Validator.check_doge,
        "bch": Validator.check_bch,
        "dash": Validator.check_dash,
        "zcash": Validator.check_zcash,
        "vtc": Validator.check_vtc,
        "eth": Validator.check_eth,
        "trx": Validator.check_trx,
    }

    if coin in validators:
        try:
            return validators[coin](address)
        except Exception:
            return ValidationResult(address, False)

    return ValidationResult(address, False)


def is_valid(address: str, coin: str = "auto") -> bool:
    """Quick check if address is valid."""
    try:
        return check_addr(address, coin).valid
    except Exception:
        return False


def get_coin_type(address: str) -> Optional[str]:
    """Get coin type from address."""
    try:
        result = Validator.check_any(address)
        return result.coin if result.valid else None
    except Exception:
        return None


def validate_multiple(
    addresses: List[str], coin: str = "auto"
) -> List[ValidationResult]:
    """Validate multiple addresses with enhanced error handling."""
    if not addresses or not isinstance(addresses, list):
        return []

    results = []
    for addr in addresses:
        try:
            results.append(check_addr(addr, coin))
        except Exception:
            results.append(ValidationResult(str(addr), False))
    return results


# Ultra-short aliases
def valid(address: str) -> bool:
    """Ultra-short validation check."""
    return is_valid(address)


def coin_type(address: str) -> Optional[str]:
    """Ultra-short coin type detection."""
    return get_coin_type(address)


def check(address: str, coin: str = "auto") -> ValidationResult:
    """Ultra-short address check."""
    return check_addr(address, coin)
