# Java Based AES Style Cipher (JBASC) is an *experimental* block cipher. 
Do not fully trust until it has been evaluated.

Attacks, Evaluations, And Improvements are welcome and requested
## Capability Summary

* Differential uniformity of 4 across all 80 SBOXs
* CT indistinguishability of 98.44%
* Avalanche of ~50%
* 512bit (64 byte) blocks
* CBC mode with PKCS7 padding
* Verified lossless roundtrip up to 2gb (my tests were capped at 2gb, probably able to do better)
* GZIP level 1 (compress-then-encrypt) compression
* Key sensitivity of 48.63%.

# Installation

jbascinstall.bet installs `%JBASC_HOME%` to your %PATH%
You then can use it like
```
jbasc encrypt "C:\path\to\file" "long-key" "good-salt"
```
for encryption
```
jbasc decrypt "C:\path\to\file.jbas" "same-long-key" "same-good-salt"
```
for decryption

# JBASC Specifications

* **Block Size:** 512 bits (64 bytes)
* **Words per Block:** 8 (64 bits each)
* **Rounds:** 10
* **IV Size:** 64 bytes (matches block size)
* **MAC:** HMAC-SHA256 (32 bytes)

## GF(2^8) Arithmetic
* GF multiplication with AES-style polynomial reduction
* Precomputed multiplication table: `GF_MUL[256][256]`
* Precomputed inverse table: `GF_INV[256]`

## GF(2) Matrix Operations
* 8x8 matrices represented as `int[8]`
* Matrix-vector multiplication: `gf2MatVecMul(M, v)`
* Matrix inversion via augmented row reduction: `gf2MatInverse(M)`

## Key Schedule
* Key derivation: SHA-256 + HKDF-style expansion
* Round keys: `roundKeys[ROUNDS][WORDS]`
* S-boxes (forward and inverse) per round and word
  * Built using GF inverse + key-dependent affine transform
  * Guaranteed invertible via LU decomposition
* Separate MAC key derived from main key

## Diffusion Layer
* **ShiftWords:** rotate each word left by its word index (0–7 bytes)
* **MixWords:** 8×8 MDS matrix over GF(2^8)
  * Ensures maximum branch number
  * Precomputed forward and inverse matrices

## Block Encryption / Decryption
* SubBytes: byte-wise S-box substitution
* ShiftWords: cross-lane rotations
* MixWords: linear diffusion (skipped in last round)
* AddRoundKey: XOR with round key
* Initial key whitening: XOR first round key and IV
* CBC-style chaining: XOR each block with previous ciphertext

## Padding
* PKCS-style padding: pad 1–64 bytes to align with block size
* Validation ensures padding is correct before unpadding

## Encrypt-then-MAC
* Layout: `IV || Ciphertext || MAC`
* Timing-safe MAC verification
* Detects tampering and throws exception if MAC fails

## Utilities
* SHA-256: `sha256(byte[]...)`
* HMAC-SHA256: `hmacSha256(byte[] key, byte[] data)`
* Byte ↔ State conversion for `long[8]` blocks
* Padding and unpadding helpers

## Security Notes
* Separate keys for cipher and MAC
* Strong diffusion: MixWords + ShiftWords
* Nonlinear S-boxes: GF inverse + affine transform
* Constant-time MAC verification
* CBC-style block chaining prevents repeating ciphertext blocks
