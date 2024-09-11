# cavp_runner
This tool helps running NIST CAVP test vectors(.rsp and .json) with open source crypto libraries.

## Crypto library support
This tool currently supports following cryptography libraries:

- OpenSSL (https://github.com/openssl/openssl)
- WolfSSL (https://www.wolfssl.com/)

Download those libraries and build it into archive(`*.a`) files. Instructions for building can be found at `libs/README_LIBBUILD.md`.

Also note that you should copy WolfSSL's headers to `include/` directory.

For your handiness, archive files and header files are already in their right position.

## Crypto algorithm support
This tool currently supports following cryptography algorithms:

- AES-GCM (256 bits key)

## How to build

Just type `make` at the top directory. That's all.

## How to run

### Manually

Download NIST test vectors from website(`.rsp` files) or via ACVTS server(`.json` files). Convert them to `.bin` file with following command:

```Shell
python test_vector_parser.py {crypto algorithm} {input file} {output file}
```
Input file must be either `*.rsp` or `*.json`. Output file must be `*.bin`.

### Automatically

CIP.