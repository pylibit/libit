#!/usr/bin/env python3
"""
Comprehensive test of all main functions in libit.
"""

print("=== Testing libit v5.3.0 ===")

# Test 1: Basic imports
try:
    from libit import gen_key, multi_wallet, btc, ltc, doge, eth, trx
    from libit import valid, check_addr, coin_type

    print("✅ All main imports successful")
except ImportError as e:
    print(f"❌ Import failed: {e}")
    exit(1)

# Test 2: Key generation
try:
    key = gen_key()
    print(f"✅ Generated key: {key[:16]}...")
except Exception as e:
    print(f"❌ Key generation failed: {e}")

# Test 3: Multi-wallet
try:
    wallet = multi_wallet(key)
    btc_info = wallet.btc()
    eth_info = wallet.eth()
    print(f"✅ Multi-wallet BTC: {btc_info.addresses.legacy[:10]}...")
    print(f"✅ Multi-wallet ETH: {eth_info['address'][:10]}...")
except Exception as e:
    print(f"❌ Multi-wallet failed: {e}")

# Test 4: Ultra-short functions
try:
    btc_wallet = btc()
    ltc_wallet = ltc()
    doge_wallet = doge()
    eth_wallet = eth()
    trx_wallet = trx()
    print("✅ Ultra-short functions work")
    print(f"  BTC: {btc_wallet.addresses.legacy[:10]}...")
    print(f"  LTC: {ltc_wallet.addresses.legacy[:10]}...")
    print(f"  DOGE: {doge_wallet.addresses.legacy[:10]}...")
    print(f"  ETH: {eth_wallet['address'][:10]}...")
    print(f"  TRX: {trx_wallet['address'][:10]}...")
except Exception as e:
    print(f"❌ Ultra-short functions failed: {e}")

# Test 5: Address validation
try:
    btc_addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    eth_addr = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"

    btc_valid = valid(btc_addr)
    eth_valid = valid(eth_addr)

    btc_check = check_addr(btc_addr)
    btc_coin = coin_type(btc_addr)

    print(f"✅ BTC address validation: {btc_valid}")
    print(f"✅ ETH address validation: {eth_valid}")
    print(f"✅ BTC detailed check: {btc_check.valid}")
    print(f"✅ BTC coin type: {btc_coin}")
except Exception as e:
    print(f"❌ Address validation failed: {e}")

# Test 6: Legacy functions
try:
    from libit import privatekey_addr, Ethereum, tron

    legacy_addr = privatekey_addr(key)
    eth_obj = Ethereum(key)  # Pass private key
    tron_obj = tron(key)  # Pass private key

    print(f"✅ Legacy functions work")
    print(f"  Legacy BTC: {legacy_addr[:10]}...")
    print(f"  Legacy ETH: {eth_obj.get_address()[:10]}...")
    print(f"  Legacy TRX: {tron_obj.get_address()[:10]}...")
except Exception as e:
    print(f"❌ Legacy functions failed: {e}")

print("\n=== All tests completed ===")
