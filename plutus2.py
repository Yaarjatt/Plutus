from ecdsa import SigningKey, SECP256k1
import hashlib
import binascii
import os
import sys
import time
import platform
import multiprocessing

DATABASE = r'database/11_13_2022/'
OUTPUT_FILE = 'plutus.txt'

def generate_private_key():
    return binascii.hexlify(os.urandom(32)).decode('utf-8').upper()

def private_key_to_public_key(private_key):
    sk = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
    vk = sk.verifying_key
    return '04' + vk.to_string().hex().upper()

def public_key_to_address(public_key):
    output = []
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    var = hashlib.new('ripemd160')
    encoding = binascii.unhexlify(public_key.encode())
    var.update(hashlib.sha256(encoding).digest())
    var_encoded = ('00' + var.hexdigest()).encode()
    digest = hashlib.sha256(binascii.unhexlify(var_encoded)).digest()
    var_hex = '00' + var.hexdigest() + hashlib.sha256(digest).hexdigest()[0:8]
    count = [char != '0' for char in var_hex].index(True) // 2
    n = int(var_hex, 16)
    while n > 0:
        n, remainder = divmod(n, 58)
        output.append(alphabet[remainder])
    for i in range(count): output.append(alphabet[0])
    return ''.join(output[::-1])

def private_key_to_wif(private_key):
    digest = hashlib.sha256(binascii.unhexlify('80' + private_key)).hexdigest()
    var = hashlib.sha256(binascii.unhexlify(digest)).hexdigest()
    var = binascii.unhexlify('80' + private_key + var[0:8])
    alphabet = chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    value = pad = 0
    result = ''
    for i, c in enumerate(var[::-1]): value += 256**i * c
    while value >= len(alphabet):
        div, mod = divmod(value, len(alphabet))
        result, value = chars[mod] + result, div
    result = chars[value] + result
    for c in var:
        if c == 0: pad += 1
        else: break
    return chars[0] * pad + result

def main(database, args):
    while True:
        private_key = generate_private_key()
        public_key = private_key_to_public_key(private_key)
        address = public_key_to_address(public_key)

        if args['verbose']:
            print(address)

        if address[-args['substring']:] in database:
            for filename in os.listdir(DATABASE):
                with open(DATABASE + filename) as file:
                    if address in file.read():
                        with open(OUTPUT_FILE, 'a') as output:
                            output.write(f'Address: {address}\n')
                            output.write(f'Private Key: {private_key}\n')
                            output.write(f'WIF: {private_key_to_wif(private_key)}\n')
                            output.write(f'Public Key: {public_key}\n\n')
                        break

def print_help():
    print('''Plutus Address Checker

Quick start: run command 'python3 plutus_checker.py'

By default, this program runs with parameters:
python3 plutus_checker.py verbose=0 substring=8

verbose: must be 0 or 1. If 1, then every generated Bitcoin address will be printed to the terminal. By default, verbose is 0.

substring: to make the program memory efficient, the entire Bitcoin address is not loaded from the database. Only the last <substring> characters are loaded. This significantly reduces the amount of RAM required to run the program. If you still get memory errors, try making this number smaller. By default, it is set to 8.

cpu_count: number of cores to run concurrently. More cores = more resource usage but faster checking. Omit this parameter to run with the maximum number of cores.''')
    sys.exit(0)

if __name__ == '__main__':
    args = {
        'verbose': 0,
        'substring': 8,
        'fastecdsa': platform.system() in ['Linux', 'Darwin'],
        'cpu_count': multiprocessing.cpu_count(),
    }
    
    for arg in sys.argv[1:]:
        command = arg.split('=')[0]
        if command == 'help':
            print_help()
        elif command == 'cpu_count':
            cpu_count = int(arg.split('=')[1])
            if cpu_count > 0 and cpu_count <= multiprocessing.cpu_count():
                args['cpu_count'] = cpu_count
            else:
                print('invalid input. cpu_count must be greater than 0 and less than or equal to ' + str(multiprocessing.cpu_count()))
                sys.exit(-1)
        elif command == 'verbose':
            verbose = arg.split('=')[1]
            if verbose in ['0', '1']:
                args['verbose'] = int(verbose)
            else:
                print('invalid input. verbose must be 0(false) or 1(true)')
                sys.exit(-1)
        elif command == 'substring':
            substring = int(arg.split('=')[1])
            if substring > 0 and substring < 27:
                args['substring'] = substring
            else:
                print('invalid input. substring must be greater than 0 and less than 27')
                sys.exit(-1)
        else:
            print('invalid input: ' + command  + '\nrun `python3 plutus_checker.py help` for help')
            sys.exit(-1)

    print('reading database files...')
    database = set()
    for filename in os.listdir(DATABASE):
        with open(DATABASE + filename) as file:
            for address in file:
                address = address.strip()
                if address.startswith('1'):
                    database.add(address[-args['substring']:])
    print('DONE')

    print(f'database size: {len(database)}')
    print(f'processes spawned: {args["cpu_count"]}')
    
    for cpu in range(args['cpu_count']):
        multiprocessing.Process(target=main, args=(database, args)).start()
