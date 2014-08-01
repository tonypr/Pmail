Searchable-Symmetric-Encryption
===============================

Pmail is a chrome extension that integrates with Gmail to make your email private.

Pmail encrypts and decrypts your messages for you while also maintaing the ability to search your emails securely.

## Encryption
Encryption and decryption of user information is taken care of by [ShadowCrypt](http://shadowcrypt-release.weebly.com/), an extension which this project is built upon. User input is encrypted with the AES-CCM encryption scheme with a randomly generated 128-bit key. 

## Secure Search Protocol
To provide the searching capability, the extension implements a secure search protocol based on the paper ["Practical Dynamic Searchable Encryption with Small Leakage"](http://eprint.iacr.org/2013/832.pdf).

### TODO:
- Change from symmetric encryption to public key encryption.
- Fix bugs when entering search text and other inputs.