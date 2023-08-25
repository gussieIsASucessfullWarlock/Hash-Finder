"""
Given a file that contains a list of plain text values, this script will hash each value with multiple hashing algorithms, such as
- MD5
- SHA1
- SHA256
- SHA512
- NTLM
- LM
- RIPEMD160
- WHIRLPOOL
- BLAKE2B512
- BLAKE2S256
- SHA3-224
- SHA3-256
- SHA3-384
- SHA3-512
- SHA512-224
- SHA512-256
- SHAKE128
- SHAKE256
- SM3
- MD4
- RMD160
"""

import argparse
import hashlib
import os
import sys
import time
from multiprocessing import Pool, cpu_count

def get_args():
    parser = argparse.ArgumentParser(description="Given a file that contains a list of plain text values, this script will hash each value with multiple hashing algorithms, such as MD5, SHA1, SHA256, SHA512, NTLM, LM, RIPEMD160, WHIRLPOOL")
    parser.add_argument("-f", "--file", help="File to read from")
    parser.add_argument("-a", "--algorithms", help="Algorithms to use", nargs="+", choices=["md4", "md5", "rmd160", "sha1", "sha224", "sha256", "sha3-224", "sha3-256", "sha3-384", "sha3-512", "sha384", "sha512", "sha512-224", "sha512-256", "shake128", "shake256", "sm3", "ntlm", "lm", "ripemd160", "whirlpool", "blake2b512", "blake2s256"])
    parser.add_argument("-v", "--value", help="Value to find")
    parser.add_argument("-l", "--list", help="List all available algorithms", action="store_true")
    args = parser.parse_args()
    if args.list:
        print("Available algorithms:")
        print("""md4
md5
rmd160
sha1
sha224
sha256
sha3-224
sha3-256
sha3-384
sha3-512
sha384
sha512
sha512-224
sha512-256
shake128
shake256
sm3
ntlm
lm
ripemd160
whirlpool
blake2b512
blake2s256""")
        sys.exit(0)
    if not args.file:
        parser.error("Please specify a file to read from")
    if not args.algorithms:
        parser.error("Please specify at least one algorithm to use")
    return args

def get_hash(algorithm, value):
    """
    Given an algorithm and a value, this function will return the hash of the value
    """
    algorithm = algorithm.lower()
    if algorithm == "md4":
        return hashlib.new("md4", value.encode()).hexdigest()
    elif algorithm == "md5":
        return hashlib.md5(value.encode()).hexdigest()
    elif algorithm == "rmd160":
        return hashlib.new("ripemd160", value.encode()).hexdigest()
    elif algorithm == "sha1":
        return hashlib.sha1(value.encode()).hexdigest()
    elif algorithm == "sha224":
        return hashlib.sha224(value.encode()).hexdigest()
    elif algorithm == "sha256":
        return hashlib.sha256(value.encode()).hexdigest()
    elif algorithm == "sha3-224":
        return hashlib.sha3_224(value.encode()).hexdigest()
    elif algorithm == "sha3-256":
        return hashlib.sha3_256(value.encode()).hexdigest()
    elif algorithm == "sha3-384":
        return hashlib.sha3_384(value.encode()).hexdigest()
    elif algorithm == "sha3-512":
        return hashlib.sha3_512(value.encode()).hexdigest()
    elif algorithm == "sha384":
        return hashlib.sha384(value.encode()).hexdigest()
    elif algorithm == "sha512":
        return hashlib.sha512(value.encode()).hexdigest()
    elif algorithm == "sha512-224":
        return hashlib.sha512_224(value.encode()).hexdigest()
    elif algorithm == "sha512-256":
        return hashlib.sha512_256(value.encode()).hexdigest()
    elif algorithm == "shake128":
        return hashlib.shake_128(value.encode()).hexdigest(16)
    elif algorithm == "shake256":
        return hashlib.shake_256(value.encode()).hexdigest(32)
    elif algorithm == "sm3":
        return hashlib.new("sm3", value.encode()).hexdigest()
    elif algorithm == "ntlm":
        return hashlib.new("md4", value.encode("utf-16le")).hexdigest()
    elif algorithm == "lm":
        return hashlib.new("lm", value.encode("utf-16le")).hexdigest()
    elif algorithm == "ripemd160":
        return hashlib.new("ripemd160", value.encode()).hexdigest()
    elif algorithm == "whirlpool":
        return hashlib.new("whirlpool", value.encode()).hexdigest()
    elif algorithm == "blake2b512":
        return hashlib.new("blake2b512", value.encode()).hexdigest()
    elif algorithm == "blake2s256":
        return hashlib.new("blake2s256", value.encode()).hexdigest()
    else:
        return None

def find_value(args):
    # Read file
    with open(args.file, "r") as file:
        values = file.read().splitlines()
        for value in values:
            value = value.strip()
            if not value:
                continue
            # Hash value
            start_time = time.time()
            pool = Pool(cpu_count())
            results = [pool.apply_async(get_hash, args=(algorithm, value)) for algorithm in args.algorithms]
            pool.close()
            pool.join()
            for result in results:
                if result.get():
                    print("[+] Value \"{}\" corresponds with \"{}\" found in {} seconds".format(result.get(), value, time.time() - start_time))
                    sys.exit(0)
            print("[-] {} not found in {} seconds".format(value, time.time() - start_time))
    
    print("[-] {} not found".format(args.value))

def main():
    """
    Read Args and hash values
    """
    args = get_args()
    if not os.path.isfile(args.file):
        print("[-] {} does not exist".format(args.file))
        sys.exit(1)
    if not os.access(args.file, os.R_OK):
        print("[-] {} access denied".format(args.file))
        sys.exit(1)
    if not args.algorithms:
        print("[-] Please specify at least one algorithm to use")
        sys.exit(1)
    if not args.value:
        # output each line and its hash value
        with open(args.file, "r") as file:
            values = file.read().splitlines()
            cLine = 1
            for value in values:
                value = value.strip()
                if not value:
                    continue
                for algorithm in args.algorithms:
                    print("Line " + str(cLine) + ": {}".format(value))
                    print("{}: {}".format(algorithm, get_hash(algorithm, value)))
                    cLine += 1
    else:
        find_value(args)
main()