# Ed25519 PEM to OpenPGP

Warning: right now there are no guarantees that the generated OpenPGP key actually corresponds with the input. Use at your own risk.

Convert Ed25519 private keys in PEM PKCS#8 format, used by for example OpenSSL and OpenVPN, to an OpenPGP key.

Usage:
```bash
sudo apt install maven
# passphrase will be used to encrypt output, PEM file must be unencrypted
mvn compile exec:java -Dexec.args="-a identity passphrase pemfile.pem"
gpg --import secret.asc
```

Example PEM file:
```
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEILoHRCRqy/UtyQwbswbxxqyWdblTcCGlyHLSb66w3ObR
-----END PRIVATE KEY-----
```

When the -a flag is given, ASCII armored output is used, the private key is stored in secret.asc and the public key in pub.asc. Otherwise secret.bpg and pub.bpg is used.
