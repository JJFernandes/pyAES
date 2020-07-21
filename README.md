# pyAES
AES python implementation using a 128 bit block size

Encryption and Decryption are provided

# Usage
```
python aes.py -e -i <filename> -o <filename> -k <32 char hex string>
python aes.py --encrypt --input-file <filename> --output-file <filename> --key <32 char hex string>
```

# Notes For Self
Change the tool to overwrite the orginal file, because using security tools like Autopsy on an OS image will allow you to view "deleted" files (hidden files marked as usuable disk space)

Change the key input to normal password inputs and send through hash function to get 16 byte key

## Sources
Cryptography and Network Security: Principles and Practice, 7th Edition

Nist Publication on Advanced Encryption Standard (AES)