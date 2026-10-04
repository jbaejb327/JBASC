# Java Based AES Style Cipher (JBASC) is an *experimental* block cipher. 
Do not fully trust until it has been evaluated.

Attacks, Evaluations, And Improvements are welcome and requested, more info at end of README.md

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


For more info, check LICENSE.
# JBASC Specifications

- 512 bit blocks
  
- 8 words per block
  
- 10 rounds
  
- 64 byte iv
  
- hmac-sha256 aead

- GF(2^8) Arithmetic

- GF(2) Matrix Operations

- GF inversion derived, key dependent substitution boxes

- 8x8 cauchy MDS matrix

- rotation based per-word diffusion (only to compliment the mds)

- cbc mode

- pkcs7# style padding


### This cipher is experimental. I am explicitly requesting:
*differential/linear trail analysis
*boomerang/rectangle attacks
*related‑key attacks
*meet‑in‑the‑middle
*impossible differentials
*algebraic attacks
*distinguishers on reduced rounds
*structural weaknesses in S‑box/key schedule coupling

Please report any attacks, distinguishers, or non‑random behavior you find.
