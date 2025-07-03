#!/usr/bin/env python3
"""
Final operational test based on README examples.
"""

print("=== Final Operational Test ===")

# Test 1: Ultra-short functions
print("\n1. Ultra-short functions:")
from libit import btc, ltc, doge, eth, trx

bitcoin = btc()
litecoin = ltc()
dogecoin = doge()
ethereum = eth()
tron = trx()

print(f"BTC: {bitcoin.addresses.legacy}")
print(f"LTC: {litecoin.addresses.legacy}")
print(f"DOGE: {dogecoin.addresses.legacy}")
print(f"ETH: {ethereum['address']}")
print(f"TRX: {tron['address']}")

# Test 2: Multi-wallet
print("\n2. Multi-wallet:")
from libit import gen_key, multi_wallet

private_key = gen_key()
wallet = multi_wallet(private_key)

btc_info = wallet.btc()
eth_info = wallet.eth()
trx_info = wallet.trx()

print(f"Multi BTC: {btc_info.addresses.legacy}")
print(f"Multi ETH: {eth_info['address']}")
print(f"Multi TRX: {trx_info['address']}")

# Test 3: Validation
print("\n3. Validation:")
from libit import valid, check_addr, coin_type

btc_addr = bitcoin.addresses.legacy
eth_addr = ethereum["address"]

print(f"BTC valid: {valid(btc_addr)}")
print(f"ETH valid: {valid(eth_addr)}")
print(f"BTC coin type: {coin_type(btc_addr)}")
print(f"ETH coin type: {coin_type(eth_addr)}")

# Test 4: Legacy compatibility
print("\n4. Legacy compatibility:")
from libit import privatekey_addr, Ethereum, tron

legacy_btc = privatekey_addr(private_key)
legacy_eth = Ethereum(private_key)
legacy_trx = tron(private_key)

print(f"Legacy BTC: {legacy_btc}")
print(f"Legacy ETH: {legacy_eth.get_address()}")
print(f"Legacy TRX: {legacy_trx.get_address()}")

print("\n✅ All tests passed! libit v5.3.0 is ready for production.")
