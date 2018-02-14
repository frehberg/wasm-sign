# WebAssembly Module Signature

This repository describing the design and high-level overview of the WebAssembly Module Signature (WAMS)

## Overview

The WebAssembly Module Signature shall proof authenticity and integrity of the WebAssembly module, as file or parsed.

## Requirements

The WebAssembly Module Signature shall provide the following features

- It shall be possible to sign a WebAssembly Module file without parsing
- The signature signs the serialized form being used for files and networ-transfer.
- A module shall be signed as is, completely, including the custom-sections.
- The module sections shall not be re-ordered to meet a canonical form.
- All module signatures shall be of equal size.
- It shall be possible to verify a signature without parsing of the module
- It shall be possible with simple tools to split a WebAssembly module into both parts, the signature and the signed content
- Signatures shall use the ECDSA algorithm with SHA256.
- The public key may be publicly available and may be distributed using DNS-TXT-Records.

## Proposal

- The WebAssembly module signature is a Custom-Section with type id 0, the section name must be formed by 9 characters, so all signatures have equal byte-size
- A module may contain just one signatures (may be extended in future)
- A signature signs the all present sections of the data stream, as is.
- The section name "signature" (9 chars) is the default signature.
- The payload of the custom-section contains the ECDSA signature; the complete section has octet-size 118.
- New signature-sections shall be appended to the end of a module only.
- Removing the last 118 bytes from a module-bytecode, the signature-section is cut off.
- The tool shall support secp256k1 in initial version and in future versions Ed25519 and secp384r1 (hence the reserved bytes at end)


Each signature section ist formed of a sequence of 118 octets:

Fields                   |         Bytes
------------------------ | ----------------------------------------------------------------------------- 
Section Type (Custom):   |   `0x0`
Section Size:            |   `0x84`
Section Name Length:     |   `0x9`
Section Name Octets [9]: |   `[0x115, 0x105, 0x103, 0x110, 0x97, 0x116, 0x117, 0x114, 0x101]`
Signature Type   :       |   `0x0` which stands for ECDSA/SHA256 with max digest length of max. 72 bytes
Signature length:        |   Single byte value 72 or less
Signature:               |   `[...]`
Padding bytes:           |   0..33 padding bytes filling extending the digest-length to up to 104 bytes (secp384r1)

- **Index 12** SIGNATURE_TYPE (for know only 0==secp256k1/SHA256 is defined)
- **Index 13** ECDSA_DATA_LENGTH, may range between 72 and less, filled up by padding bytes
- **Index 14** ECDSA_DATA_START, first byte of ECDSA digest
- **Index 14+ECDSA_DATA_LENGTH**, end of the digest
 
In case the digest has byte size 72 (secp256k1) the preamble looks like (followed by the ECDSA digest):
```
[0, 84, 9, 115, 105, 103, 110, 97, 116, 117, 114, 101, 0, 72 ]
```

The digest is calculated using ciphers secp256k1/SHA256.
Trailing padding bytes fill up to total length of 118 bytes.

## Usage

### Private Key Generation
This is the key that must be kept secret and is used to sign your WASM files.
```
openssl ecparam -name secp256k1 -genkey -noout -out signerkey.pem
```

### Public Key Generation
This is the key that should be published or embedded in your application.
```
openssl ec -in signerkey.pem -pubout -outform pem -out signerkey.pub.pem
```

### Signing the WASM file
The tool returns with exit code 0 on success, otherwise with error code 1
```
wasm-sign -k signerkey.pem module.wasm signed-module.wasm
```

### Verifying the WASM file
The tool returns with exit code 0 on success, otherwise with error code 1
```
wasm-sign -v -k signerkey.pub.pem signed-module.wasm
```

### Signature Example
Output of `hexdump -C signed-module.wasm`:

```
00000120  .. .. .. .. .. .. .. 00  54 09 73 69 67 6e 61 74  |j$......T.signat|
00000130  75 72 65 00 47 30 45 02  21 00 a3 32 3e 3b 82 05  |ure.G0E.!..2>;..|
00000140  e7 d1 93 8a 6a 2d 6e 8c  8c 1d 6d cd 54 5e 2d 04  |....j-n...m.T^-.|
00000150  f4 57 4f fd 00 b7 d2 7b  6f fd 02 20 56 32 33 97  |.WO....{o.. V23.|
00000160  55 7c b2 93 06 62 7b d6  0f a2 f4 e0 8f 6c b8 13  |U|...b{......l..|
00000170  0b ae c4 55 5b 37 26 52  b8 61 6e 6d 00           |...U[7&R.anm.|
0000017d
```

## Build
```
cargo build --release
```
## Unit Test
```
cargo test
```
## End2End Test
```
make test
```



