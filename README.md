
# Libit

---

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

### bytes to ethereum address

```python
from libit import bytes_eth
seed_bytes = b"Bytes data (32 bytes)"
eth_addr = bytes_eth(seed_bytes)
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
### private key to wif

convert private key (hex) to wif compressed and uncompressed

```python
import libit

pvk_hex = "hex private key"
# compressed
wif_compress = libit.pvk_to_wif(pvk_hex, True)
# uncompressed
wif_decompress = libit.pvk_to_wif(pvk_hex)
```

---

### private key to decimal

```python
import libit
pvk = "hex private key"
decimal = libit.pvk_to_decimal(pvk)
```
### private key to address

```python
import libit
pvk = "hex private key"
compress_addr = libit.privatekey_addr(pvk, True)
uncompress_addr = libit.privatekey_addr(pvk)
```
