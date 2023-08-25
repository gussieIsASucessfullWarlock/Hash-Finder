# Hash Finder

This is a Python script that reads a file containing values and hashes them using various hashing algorithms. It then searches for a match between the hashed values and a specified value.

## Requirements

- Python 3.x
- `argparse` module
- `hashlib` module

## Usage

### Arguments

- `-h, --help`: show the help message and exit
- `-f FILE, --file FILE`: path to the file containing the values to hash
- `-a ALGORITHMS [ALGORITHMS ...], --algorithms ALGORITHMS [ALGORITHMS ...]`: list of hashing algorithms to use
- `-v VALUE, --value VALUE`: value to search for

### Example

This will read the file `values.txt`, hash each value using the `md5`, `sha1`, and `sha256` algorithms, and search for a match with the value `123456`.

## Supported Algorithms

- `md5`
- `sha1`
- `sha224`
- `sha256`
- `sha384`
- `sha512`
- `sha512-224`
- `sha512-256`
- `sha3-224`
- `sha3-256`
- `sha3-384`
- `sha3-512`
- `shake128`
- `shake256`
- `sm3`
- `ntlm`
- `lm`
- `ripemd160`
- `whirlpool`
- `blake2b512`
- `blake2s256`

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.