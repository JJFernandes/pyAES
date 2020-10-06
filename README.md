# pyAES
Python implementation of AES-128-CBC encryption and decryption

Currently working on changing decryption to CBC mode as well.

# Usage
```
python aes.py --encrypt -in <file-in> --out <file-out> --key <key string> --iv <iv string>
```
Both the key and iv string should be 32 hexidecimal characters long for a 128 bit block size.


# Notes For Self


## Sources
Cryptography and Network Security: Principles and Practice, 7th Edition

Nist Publication on Advanced Encryption Standard (AES)