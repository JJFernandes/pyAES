# pyAES
AES python implementation using a 128 bit key size

Encryption and Decryption are provided

# Usage
```
python aes.py -e -i <filename> -o <filename> -k <file password string>
python aes.py --encrypt --input-file <filename> --output-file <filename> --key <file password string>
```

# Notes For Self
Change the tool to overwrite the orginal file, because using security tools like Autopsy on an OS image will allow you to view "deleted" files (hidden files marked as usuable disk space)


## Sources
Cryptography and Network Security: Principles and Practice, 7th Edition

Nist Publication on Advanced Encryption Standard (AES)