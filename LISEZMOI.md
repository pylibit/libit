

# Libit

Des utilitaires rapides et faciles pour la conversion et la génération de données de portefeuilles Bitcoin, Ethereum et Tron en Python.

## Installation et Utilisation

### Windows
```
pip install libit
```

### Linux & Mac
```
pip3 install libit
```

Générez et convertissez des clés utilitaires de base pour les informations de portefeuille et les données publiques/privées.

### Comment Faire

#### Octets vers WIF (Wallet Import Format)
```python
from libit import bytes_wif

seed_bytes = b"Données en octets (32 octets)"
# WIF compressé
wif_compress = bytes_wif(seed_bytes, True)
wif_decompress = bytes_wif(seed_bytes)
```

#### Octets vers Adresse
```python
from libit import bytes_addr

seed_bytes = b"Données en octets (32 octets)"
# Compressé
caddr = bytes_addr(seed_bytes, True)
# Non compressé
uaddr = bytes_addr(seed_bytes)
```

#### Octets vers Adresse Ethereum
```python
from libit import bytes_eth

seed_bytes = b"Données en octets (32 octets)"
eth_addr = bytes_eth(seed_bytes)
```

#### WIF vers Adresse
Convertit une clé WIF en adresse compressée et non compressée du portefeuille.

```python
import libit

wif_str = "Chaîne de données WIF"
# Compressé
caddr = libit.wif_addr(wif, True)
# Non compressé
uaddr = libit.wif_addr(wif)
```

#### Clé Privée vers WIF
Convertit une clé privée (hexadécimale) en WIF compressé et non compressé.

```python
import libit

pvk_hex = "clé privée hexadécimale"
# Compressé
wif_compress = libit.pvk_to_wif(pvk_hex, True)
# Non compressé
wif_decompress = libit.pvk_to_wif(pvk_hex)
```

#### Clé Privée vers Décimal
```python
import libit

pvk = "clé privée hexadécimale"
decimal = libit.pvk_to_decimal(pvk)
```

#### Clé Privée vers Adresse
```python
import libit

pvk = "clé privée hexadécimale"
compress_addr = libit.privatekey_addr(pvk, True)
uncompress_addr = libit.privatekey_addr(pvk)
```

## À Propos

Des utilitaires rapides et faciles pour la conversion et la génération de données de portefeuilles Bitcoin, Ethereum et Tron en Python.

---
Merci beaucoup!
