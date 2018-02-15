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
Section Type (Custom):   |   `0`
Section Size:            |   `116`
Section Name Length:     |   `9`
Section Name Octets [9]: |   `[115, 105, 103, 110, 97, 116, 117, 114, 101]` (read as  "signature")
Signature Type   :       |   `0` which stands for ECDSA/SHA256 with max digest length of max. 72 bytes
Signature length:        |   Single byte value 72 or less
Signature:               |   `[...]`
Padding bytes:           |   0..33 padding bytes filling extending the digest-length to up to 104 bytes (secp384r1)

The signature is always attached to the end of a WASM-file. If receiving a signed WASM-file, the last 118 characters can be cut off to get the WASM-Signature section. The following indeces permit verification of the signature using  command line tools or Javascript, without the need to parse the WASM-module-bytecodes:

- **Index 0..11** Fixed byte-sequence `[0, 116, 9, 115, 105, 103, 110, 97, 116, 117, 114, 101]`
- **Index 12** SIGNATURE_TYPE (the only valid value is '0' for curve secp256k1/SHA256 for now)
- **Index 13** DIGEST_DATA_LENGTH, may range between 65..104 (if using secp256k1 usually a value of 70 or 71 or 72)
- **Index 14** DIGEST_DATA_START, first byte of digest
- **Index 14+DIGEST_DATA_LENGTH**, end of the digest
 
In case the digest has byte size 72 (secp256k1) the preamble looks like (followed by the ECDSA digest):
```
[0, 116, 9, 115, 105, 103, 110, 97, 116, 117, 114, 101, 0, 72 ]
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
00000110
00000120  xx xx xx xx xx xx xx 00  74 09 73 69 67 6e 61 74  |j$......t.signat|
00000130  75 72 65 00 47 30 45 02  20 58 20 79 4b 91 52 39  |ure.G0E. X yK.R9|
00000140  75 52 69 f0 cf dc 81 8a  7c d8 ab 08 1d 49 ab c2  |uRi.....|....I..|
00000150  fa 19 79 f5 03 92 e9 9b  87 02 21 00 8f a0 ad 5a  |..y.......!....Z|
00000160  f2 55 ce cf c6 ed 82 15  5a ed 7a 47 43 d9 e5 4e  |.U......Z.zGC..N|
00000170  fd 74 79 e8 80 4e 82 9c  08 eb 8e 9a 00 00 00 00  |.ty..N..........|
00000180  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
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



