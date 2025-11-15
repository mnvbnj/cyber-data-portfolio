try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:
    print("cryptography not installed. Run: python -m pip install cryptography")
    raise

import os
import sys
import argparse

def load_or_create_key(path='secret.key', create=False):
    if os.path.exists(path):
        with open(path, 'rb') as f:
            key = f.read()
        if not key:
            raise ValueError(f"Key file is empty: {path}")
        return key
    if create:
        key = Fernet.generate_key()
        with open(path, 'wb') as f:
            f.write(key)
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
        return key
    raise FileNotFoundError(f"Key file not found: {path}")

def encrypt_file(in_path='sensitive_data.csv', out_path='sensitive_data.enc', key_path='secret.key'):
    if os.path.abspath(in_path) == os.path.abspath(out_path):
        print("Input and output paths must differ.")
        sys.exit(1)

    try:
        key = load_or_create_key(key_path, create=True)
    except Exception as e:
        print(f"Key error: {e}")
        sys.exit(1)

    fernet = Fernet(key)

    try:
        with open(in_path, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        print(f"Input file not found: {in_path}")
        sys.exit(1)
    except Exception as e:
        print(f"Failed to read input file: {e}")
        sys.exit(1)

    try:
        encrypted = fernet.encrypt(data)
        with open(out_path, 'wb') as f:
            f.write(encrypted)
    except Exception as e:
        print(f"Failed to write encrypted file: {e}")
        sys.exit(1)

    print(f"File encrypted → {out_path}")

def decrypt_file(enc_path='sensitive_data.enc', key_path='secret.key', out_path=None):
    try:
        key = load_or_create_key(key_path, create=False)
    except FileNotFoundError:
        print(f"Key not found: {key_path}. Do not create a new key when decrypting.")
        sys.exit(1)
    except Exception as e:
        print(f"Key error: {e}")
        sys.exit(1)

    fernet = Fernet(key)

    try:
        with open(enc_path, 'rb') as f:
            encrypted = f.read()
    except FileNotFoundError:
        print(f"Encrypted file not found: {enc_path}")
        sys.exit(1)
    except Exception as e:
        print(f"Failed to read encrypted file: {e}")
        sys.exit(1)

    try:
        decrypted = fernet.decrypt(encrypted)
    except InvalidToken:
        print("Decryption failed: invalid key or corrupted data (InvalidToken).")
        sys.exit(1)
    except Exception as e:
        print(f"Decryption error: {e}")
        sys.exit(1)

    if out_path:
        try:
            with open(out_path, 'wb') as f:
                f.write(decrypted)
            print(f"Decrypted to → {out_path}")
        except Exception as e:
            print(f"Failed to write decrypted file: {e}")
            sys.exit(1)
    else:
        preview = decrypted[:200]
        try:
            print("Decrypted preview:\n", preview.decode('utf-8', errors='replace'))
        except Exception:
            print("Decrypted preview (binary):", preview)

def parse_args_and_run():
    p = argparse.ArgumentParser(description="Encrypt/decrypt files with Fernet")
    sub = p.add_subparsers(dest='cmd', required=False)
    enc = sub.add_parser('encrypt', help='Encrypt a file')
    enc.add_argument('-i', '--in', dest='in_path', default='sensitive_data.csv')
    enc.add_argument('-o', '--out', dest='out_path', default='sensitive_data.enc')
    enc.add_argument('-k', '--key', dest='key_path', default='secret.key')

    dec = sub.add_parser('decrypt', help='Decrypt a file')
    dec.add_argument('-i', '--in', dest='enc_path', default='sensitive_data.enc')
    dec.add_argument('-o', '--out', dest='out_path', default=None)
    dec.add_argument('-k', '--key', dest='key_path', default='secret.key')

    args = p.parse_args()
    if args.cmd == 'decrypt':
        decrypt_file(enc_path=args.enc_path, key_path=args.key_path, out_path=args.out_path)
    else:
        # default to encrypt if no subcommand provided
        encrypt_file(in_path=getattr(args, 'in_path', 'sensitive_data.csv'),
                     out_path=getattr(args, 'out_path', 'sensitive_data.enc'),
                     key_path=getattr(args, 'key_path', 'secret.key'))

if __name__ == "__main__":
    parse_args_and_run()