
# Libit

[![Read the Docs](https://img.shields.io/readthedocs/libit)](https://libit.readthedocs.io 'libit documentation') [![GitHub commit check runs](https://img.shields.io/github/check-runs/pylibit/libit/main)](https://github.com/pylibit/libit)  [![GitHub last commit](https://img.shields.io/github/last-commit/pylibit/libit)](https://github.com/pylibit/libit)  [![GitHub commit activity](https://img.shields.io/github/commit-activity/m/pylibit/libit)](https://github.com/pylibit/libit)  [![GitHub top language](https://img.shields.io/github/languages/top/pylibit/libit)](https://github.com/pylibit/libit)  [![PyPI - Downloads](https://img.shields.io/pypi/dm/libit)](https://pypi.org/project/libit/)  [![Website](https://img.shields.io/website?url=https%3A%2F%2Flibit.readthedocs.io&up_color=blue&style=plastic)](https://libit.readthedocs.io)

Fast and easy converted and generated utils for bitcoin , ethereum and tron wallet in python

---




## install & use

### windows
```batch
pip install libit
```
### linux & mac
```shell
pip3 install libit
```

generated and convert base utils key for wallet information and public , private data

## how to 

### bytes to wif

```python
from libit import bytes_wif
seed_bytes = b"Bytes data (32 bytes)"
# wif compressed
wif_compress = bytes_wif(seed_bytes, True)
wif_decompress = bytes_wif(seed_bytes)
```
### bytes to address

```python
from libit import bytes_addr
seed_bytes = b"Bytes data (32 bytes)"
# compressed
caddr = bytes_addr(seed_bytes, True)
# uncompressed
uaddr = bytes_addr(seed_bytes)
```

### Ethereum address

```python
import libit
eth = libit.Ethereum(private_key=private_key)
# Ethereum Address
eth_addr = eth.get_address()
# Ethereum Address Hex
eth_hash = eth.get_hexAddress()

```

### Tron

Generate and Converted Private Key to Tron (TRX) Address Wallet + Hex

```python
import libit
# Tron
tron = libit.tron(private_key)
# Address Wallet
tron_addr = tron.get_address()
# TVzMud6edfxrdiyfa6ymEh7huQfWHjtiSK
# Tron Hex
tron_hex = tron.get_hexAddress()
# 41db9a5dc0e70338da631da168f8fe4d503de9c8c5
```
---
### wif to address:

convert wif key to compressed and uncompressed address wallet

```python
import libit

wif_str = "Wif Data String"
# compressed
caddr = libit.wif_addr(wif, True)
# uncompressed
uaddr = libit.wif_addr(wif)
```
---
### Passphrase

Generated and Convereted Passphrase (string) to Compressed and Uncompressed Bitcoin Address Wallet

```python
import libit

# Passphrase
pass_target = "libit"

compressed_address = libit.passphrase_addr(pass_target, True)
# output: 1MpWosiCM7PYubsi6h1QEgcHPAk3STbyzd
uncompressed_address = libit.passphrase_addr(pass_target, False)
# output: 1Dmaa5Rc3nbCq6XyQ7ytK2XTXKuNZqdGzV
```

---

### Private Key (HEX)

```python
import libit

private_key = "3e891d92f1c2af69e0f38a354247c4cc99ed39c690649a784b28eeed26a33c60"

# Decimal
decimal = libit.privatekey_decimal(private_key)
# Output: 28285658772293776204563833849098122629211544261487479808490805808188778298464

# Wif Compress and Uncompress
wif_compress = libit.privatekey_wif(private_key, True)
# output: KyKGj2ZHFv7atucKxGTTsmyCY5ZoPfanvzPd8Ev6w1SM4saVTss7
wif_decompress = libit.privatekey_wif(private_key, False)
# output: 5JHpyCECqh8PBQFM9tzCXY2rjqcXSymp7LoMsaWhmQfNKAnrt9z

# Bitcoin Address Compress and Uncompress
btc_compress = libit.privatekey_addr(private_key, True)
# output: 1EwmhfQhsMsYWSd2VwgmxmcSPjVXuovPVa
btc_decompress = libit.privatekey_addr(private_key, False)
# output: 16KuHiP42KTxbPJc3y4DmjToRZXX9ePEyH

# Ethereum Address and Hex Address
eth = libit.Ethereum(private_key=private_key)
eth_addr = eth.get_address()
# output: 0xdb9a5dc0e70338da631da168f8fe4d503de9c8c5
eth_hex = eth.get_hexAddress()
# output: 3e891d92f1c2af69e0f38a354247c4cc99ed39c690649a784b28eeed26a33c60

# Tron Address and Hex Address (Hash)
tron = libit.tron(private_key=private_key)
tron_addr = tron.get_address()
# output: TVzMud6edfxrdiyfa6ymEh7huQfWHjtiSK
tron_hex = tron.get_hexAddress()
# output: 41db9a5dc0e70338da631da168f8fe4d503de9c8c5
```

### Reuse Method

Extract Private Key and Public Key From Transaction ID (hash) for reuse type wallet.

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

