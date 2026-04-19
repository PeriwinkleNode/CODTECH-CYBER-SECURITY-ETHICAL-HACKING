#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║           ADVANCED ENCRYPTION TOOL                   ║
║   AES-256-GCM · ChaCha20-Poly1305 · RSA-2048        ║
║   File & Text encryption with password or key file   ║
╚══════════════════════════════════════════════════════╝

Dependencies: pip install cryptography
"""

import argparse
import base64
import getpass
import json
import os
import sys
import time
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidTag
except ImportError:
    print("[ERROR] Missing dependency. Run: pip install cryptography")
    sys.exit(1)

BANNER = r"""
  ╔═══════════════════════════════════════════════════╗
  ║   ███████╗███╗   ██╗ ██████╗██████╗ ██╗   ██╗   ║
  ║   ██╔════╝████╗  ██║██╔════╝██╔══██╗╚██╗ ██╔╝   ║
  ║   █████╗  ██╔██╗ ██║██║     ██████╔╝ ╚████╔╝    ║
  ║   ██╔══╝  ██║╚██╗██║██║     ██╔══██╗  ╚██╔╝     ║
  ║   ███████╗██║ ╚████║╚██████╗██║  ██║   ██║      ║
  ║   ╚══════╝╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝   ╚═╝      ║
  ║         ADVANCED ENCRYPTION TOOL v1.0             ║
  ╚═══════════════════════════════════════════════════╝
"""

ENCRYPTED_EXT = ".enc"
KEY_EXT = ".key"

# ─────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────

def print_header(title: str):
    print(f"\n  ╔{'═'*50}╗")
    print(f"  ║  {title:<48}║")
    print(f"  ╚{'═'*50}╝")

def ok(msg):   print(f"  ✔  {msg}")
def warn(msg): print(f"  ⚠  {msg}")
def fail(msg): print(f"  ✘  {msg}")
def info(msg): print(f"  ℹ  {msg}")

def confirm(prompt: str) -> bool:
    return input(f"  {prompt} [y/N]: ").strip().lower() == "y"

def read_password(prompt="Password") -> bytes:
    pw = getpass.getpass(f"  {prompt}: ")
    return pw.encode()

def file_size_str(path: str) -> str:
    size = os.path.getsize(path)
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


# ─────────────────────────────────────────────────────
# Key Derivation  (password → 32-byte key)
# ─────────────────────────────────────────────────────

def derive_key_scrypt(password: bytes, salt: bytes) -> bytes:
    """High-strength key derivation using Scrypt (N=2^17)."""
    kdf = Scrypt(salt=salt, length=32, n=2**17, r=8, p=1, backend=default_backend())
    return kdf.derive(password)

def derive_key_pbkdf2(password: bytes, salt: bytes, iterations: int = 600_000) -> bytes:
    """PBKDF2-HMAC-SHA256 key derivation (NIST recommended)."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=iterations, backend=default_backend())
    return kdf.derive(password)


# ─────────────────────────────────────────────────────
# MODULE 1 — AES-256-GCM  (symmetric, password-based)
# ─────────────────────────────────────────────────────

def aes_encrypt_data(data: bytes, password: bytes) -> bytes:
    salt  = os.urandom(32)
    nonce = os.urandom(12)
    key   = derive_key_scrypt(password, salt)
    ct    = AESGCM(key).encrypt(nonce, data, None)
    # Layout: [4-byte magic][salt 32][nonce 12][ciphertext+tag]
    return b"AE01" + salt + nonce + ct

def aes_decrypt_data(data: bytes, password: bytes) -> bytes:
    if not data.startswith(b"AE01"):
        raise ValueError("Not a valid AES-256-GCM encrypted file.")
    salt  = data[4:36]
    nonce = data[36:48]
    ct    = data[48:]
    key   = derive_key_scrypt(password, salt)
    try:
        return AESGCM(key).decrypt(nonce, ct, None)
    except InvalidTag:
        raise ValueError("Decryption failed — wrong password or file is corrupted.")

def aes_encrypt_file(input_path: str, output_path: str = None):
    print_header("AES-256-GCM FILE ENCRYPTION")
    pw  = read_password("Enter password")
    pw2 = read_password("Confirm password")
    if pw != pw2:
        fail("Passwords do not match."); return

    out = output_path or input_path + ENCRYPTED_EXT
    info(f"Input  : {input_path}  ({file_size_str(input_path)})")
    info(f"Output : {out}")
    info("Deriving key with Scrypt (this may take a moment)...")

    t0 = time.time()
    with open(input_path, "rb") as f:
        plaintext = f.read()
    ct = aes_encrypt_data(plaintext, pw)
    with open(out, "wb") as f:
        f.write(ct)

    ok(f"Encrypted in {time.time()-t0:.2f}s → {out}  ({file_size_str(out)})")

def aes_decrypt_file(input_path: str, output_path: str = None):
    print_header("AES-256-GCM FILE DECRYPTION")
    pw = read_password("Enter password")

    out = output_path or (input_path[:-len(ENCRYPTED_EXT)] if input_path.endswith(ENCRYPTED_EXT) else input_path + ".dec")
    info(f"Input  : {input_path}  ({file_size_str(input_path)})")
    info(f"Output : {out}")

    t0 = time.time()
    try:
        with open(input_path, "rb") as f:
            ct = f.read()
        plaintext = aes_decrypt_data(ct, pw)
        with open(out, "wb") as f:
            f.write(plaintext)
        ok(f"Decrypted in {time.time()-t0:.2f}s → {out}  ({file_size_str(out)})")
    except ValueError as e:
        fail(str(e))


# ─────────────────────────────────────────────────────
# MODULE 2 — ChaCha20-Poly1305  (modern stream cipher)
# ─────────────────────────────────────────────────────

def chacha_encrypt_data(data: bytes, password: bytes) -> bytes:
    salt  = os.urandom(32)
    nonce = os.urandom(12)
    key   = derive_key_scrypt(password, salt)
    ct    = ChaCha20Poly1305(key).encrypt(nonce, data, None)
    return b"CC01" + salt + nonce + ct

def chacha_decrypt_data(data: bytes, password: bytes) -> bytes:
    if not data.startswith(b"CC01"):
        raise ValueError("Not a valid ChaCha20-Poly1305 encrypted file.")
    salt  = data[4:36]
    nonce = data[36:48]
    ct    = data[48:]
    key   = derive_key_scrypt(password, salt)
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ct, None)
    except InvalidTag:
        raise ValueError("Decryption failed — wrong password or file is corrupted.")

def chacha_encrypt_file(input_path: str, output_path: str = None):
    print_header("ChaCha20-Poly1305 FILE ENCRYPTION")
    pw  = read_password("Enter password")
    pw2 = read_password("Confirm password")
    if pw != pw2:
        fail("Passwords do not match."); return

    out = output_path or input_path + ENCRYPTED_EXT
    info("Deriving key with Scrypt...")
    t0 = time.time()
    with open(input_path, "rb") as f:
        plaintext = f.read()
    ct = chacha_encrypt_data(plaintext, pw)
    with open(out, "wb") as f:
        f.write(ct)
    ok(f"Encrypted in {time.time()-t0:.2f}s → {out}")

def chacha_decrypt_file(input_path: str, output_path: str = None):
    print_header("ChaCha20-Poly1305 FILE DECRYPTION")
    pw = read_password("Enter password")
    out = output_path or (input_path[:-len(ENCRYPTED_EXT)] if input_path.endswith(ENCRYPTED_EXT) else input_path + ".dec")
    t0 = time.time()
    try:
        with open(input_path, "rb") as f:
            ct = f.read()
        plaintext = chacha_decrypt_data(ct, pw)
        with open(out, "wb") as f:
            f.write(plaintext)
        ok(f"Decrypted in {time.time()-t0:.2f}s → {out}")
    except ValueError as e:
        fail(str(e))


# ─────────────────────────────────────────────────────
# MODULE 3 — Text Encryption (AES-256-GCM, base64 out)
# ─────────────────────────────────────────────────────

def encrypt_text(plaintext: str, password: bytes) -> str:
    ct = aes_encrypt_data(plaintext.encode(), password)
    return base64.b64encode(ct).decode()

def decrypt_text(ciphertext_b64: str, password: bytes) -> str:
    ct = base64.b64decode(ciphertext_b64)
    return aes_decrypt_data(ct, password).decode()

def text_encrypt_interactive():
    print_header("TEXT ENCRYPTION  (AES-256-GCM)")
    text = input("  Enter text to encrypt: ")
    pw   = read_password("Password")
    pw2  = read_password("Confirm password")
    if pw != pw2:
        fail("Passwords do not match."); return
    result = encrypt_text(text, pw)
    print(f"\n  Encrypted (base64):\n  {result}\n")

def text_decrypt_interactive():
    print_header("TEXT DECRYPTION  (AES-256-GCM)")
    ct = input("  Paste encrypted text: ").strip()
    pw = read_password("Password")
    try:
        result = decrypt_text(ct, pw)
        print(f"\n  Decrypted text:\n  {result}\n")
    except Exception as e:
        fail(str(e))


# ─────────────────────────────────────────────────────
# MODULE 4 — RSA-2048 Key Pair Generation & Encryption
# ─────────────────────────────────────────────────────

def generate_rsa_keypair(key_dir: str = "."):
    print_header("RSA-2048 KEY PAIR GENERATION")
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    pw = read_password("Password to protect private key (leave blank for none)")

    encryption = (
        serialization.BestAvailableEncryption(pw) if pw
        else serialization.NoEncryption()
    )

    priv_path = os.path.join(key_dir, "private.pem")
    pub_path  = os.path.join(key_dir, "public.pem")

    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            encryption,
        ))
    with open(pub_path, "wb") as f:
        f.write(private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    ok(f"Private key → {priv_path}")
    ok(f"Public key  → {pub_path}")
    warn("Keep your private key safe. Never share it.")

def rsa_encrypt_file(input_path: str, pub_key_path: str, output_path: str = None):
    """Hybrid encryption: AES-256 key encrypted with RSA public key."""
    print_header("RSA HYBRID FILE ENCRYPTION")
    with open(pub_key_path, "rb") as f:
        pub_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

    # Generate a random AES session key
    session_key = os.urandom(32)
    nonce = os.urandom(12)

    with open(input_path, "rb") as f:
        plaintext = f.read()

    # Encrypt data with AES-256-GCM
    ct = AESGCM(session_key).encrypt(nonce, plaintext, None)

    # Encrypt session key with RSA-OAEP
    enc_key = pub_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
    )

    out = output_path or input_path + ".rsa.enc"
    # Layout: [2-byte key_len][enc_key][nonce 12][ciphertext]
    key_len = len(enc_key).to_bytes(2, "big")
    with open(out, "wb") as f:
        f.write(b"RS01" + key_len + enc_key + nonce + ct)

    ok(f"Encrypted → {out}")
    info("Decrypt with your private key.")

def rsa_decrypt_file(input_path: str, priv_key_path: str, output_path: str = None):
    print_header("RSA HYBRID FILE DECRYPTION")
    pw = read_password("Private key password (leave blank if none)")
    password = pw if pw else None

    with open(priv_key_path, "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=password, backend=default_backend())

    with open(input_path, "rb") as f:
        data = f.read()

    if not data.startswith(b"RS01"):
        fail("Not a valid RSA-encrypted file."); return

    key_len = int.from_bytes(data[4:6], "big")
    enc_key = data[6:6+key_len]
    nonce   = data[6+key_len:6+key_len+12]
    ct      = data[6+key_len+12:]

    try:
        session_key = priv_key.decrypt(
            enc_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            )
        )
        plaintext = AESGCM(session_key).decrypt(nonce, ct, None)
    except Exception as e:
        fail(f"Decryption failed: {e}"); return

    out = output_path or input_path.replace(".rsa.enc", ".dec")
    with open(out, "wb") as f:
        f.write(plaintext)
    ok(f"Decrypted → {out}")


# ─────────────────────────────────────────────────────
# MODULE 5 — Secure File Wipe
# ─────────────────────────────────────────────────────

def secure_wipe(path: str, passes: int = 3):
    print_header("SECURE FILE WIPE")
    if not confirm(f"Permanently wipe '{path}'? This cannot be undone."):
        info("Cancelled."); return
    size = os.path.getsize(path)
    info(f"Wiping {path}  ({file_size_str(path)}) with {passes} pass(es)...")
    with open(path, "r+b") as f:
        for i in range(passes):
            f.seek(0)
            f.write(os.urandom(size))
            f.flush()
            os.fsync(f.fileno())
            info(f"Pass {i+1}/{passes} complete")
    os.remove(path)
    ok(f"'{path}' securely wiped and deleted.")


# ─────────────────────────────────────────────────────
# MODULE 6 — Hash File
# ─────────────────────────────────────────────────────

def hash_file(path: str):
    print_header(f"FILE HASH  →  {path}")
    algorithms = {
        "MD5"    : hashes.MD5(),
        "SHA-1"  : hashes.SHA1(),
        "SHA-256": hashes.SHA256(),
        "SHA-512": hashes.SHA512(),
    }
    with open(path, "rb") as f:
        data = f.read()
    from cryptography.hazmat.primitives import hashes as h_mod
    from cryptography.hazmat.backends import default_backend as db
    for name, algo in algorithms.items():
        from cryptography.hazmat.primitives.hashes import Hash
        digest = Hash(algo, backend=db())
        digest.update(data)
        print(f"  {name:<10}: {digest.finalize().hex()}")


# ─────────────────────────────────────────────────────
# Interactive Menu
# ─────────────────────────────────────────────────────

MENU = """
  ┌─────────────────────────────────────────────────┐
  │               MAIN MENU                         │
  ├─────────────────────────────────────────────────┤
  │  FILE ENCRYPTION (AES-256-GCM)                  │
  │    1. Encrypt file                              │
  │    2. Decrypt file                              │
  ├─────────────────────────────────────────────────┤
  │  FILE ENCRYPTION (ChaCha20-Poly1305)            │
  │    3. Encrypt file                              │
  │    4. Decrypt file                              │
  ├─────────────────────────────────────────────────┤
  │  TEXT ENCRYPTION (AES-256-GCM + Base64)         │
  │    5. Encrypt text                              │
  │    6. Decrypt text                              │
  ├─────────────────────────────────────────────────┤
  │  RSA-2048 ASYMMETRIC                            │
  │    7. Generate RSA key pair                     │
  │    8. Encrypt file with public key              │
  │    9. Decrypt file with private key             │
  ├─────────────────────────────────────────────────┤
  │  UTILITIES                                      │
  │   10. Hash a file (MD5/SHA1/SHA256/SHA512)      │
  │   11. Secure file wipe                          │
  │    0. Exit                                      │
  └─────────────────────────────────────────────────┘
"""

def interactive_menu():
    print(BANNER)
    while True:
        print(MENU)
        choice = input("  Select option: ").strip()

        if choice == "1":
            p = input("  Input file path: ").strip()
            aes_encrypt_file(p)
        elif choice == "2":
            p = input("  Encrypted file path: ").strip()
            aes_decrypt_file(p)
        elif choice == "3":
            p = input("  Input file path: ").strip()
            chacha_encrypt_file(p)
        elif choice == "4":
            p = input("  Encrypted file path: ").strip()
            chacha_decrypt_file(p)
        elif choice == "5":
            text_encrypt_interactive()
        elif choice == "6":
            text_decrypt_interactive()
        elif choice == "7":
            d = input("  Output directory (default: current): ").strip() or "."
            generate_rsa_keypair(d)
        elif choice == "8":
            f = input("  Input file path: ").strip()
            k = input("  Public key path (default: public.pem): ").strip() or "public.pem"
            rsa_encrypt_file(f, k)
        elif choice == "9":
            f = input("  Encrypted file path: ").strip()
            k = input("  Private key path (default: private.pem): ").strip() or "private.pem"
            rsa_decrypt_file(f, k)
        elif choice == "10":
            p = input("  File path: ").strip()
            hash_file(p)
        elif choice == "11":
            p = input("  File to wipe: ").strip()
            secure_wipe(p)
        elif choice == "0":
            print("\n  Goodbye.\n"); break
        else:
            warn("Invalid option. Try again.")


# ─────────────────────────────────────────────────────
# CLI  (non-interactive mode)
# ─────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Encryption Tool — AES-256-GCM / ChaCha20 / RSA-2048",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd")

    # AES
    ae = sub.add_parser("aes-encrypt", help="AES-256-GCM encrypt a file")
    ae.add_argument("input"); ae.add_argument("--output", default=None)

    ad = sub.add_parser("aes-decrypt", help="AES-256-GCM decrypt a file")
    ad.add_argument("input"); ad.add_argument("--output", default=None)

    # ChaCha20
    ce = sub.add_parser("chacha-encrypt", help="ChaCha20-Poly1305 encrypt a file")
    ce.add_argument("input"); ce.add_argument("--output", default=None)

    cd = sub.add_parser("chacha-decrypt", help="ChaCha20-Poly1305 decrypt a file")
    cd.add_argument("input"); cd.add_argument("--output", default=None)

    # RSA
    rg = sub.add_parser("rsa-keygen", help="Generate RSA-2048 key pair")
    rg.add_argument("--dir", default=".")

    re = sub.add_parser("rsa-encrypt", help="RSA hybrid encrypt a file")
    re.add_argument("input"); re.add_argument("--pubkey", default="public.pem")

    rd = sub.add_parser("rsa-decrypt", help="RSA hybrid decrypt a file")
    rd.add_argument("input"); rd.add_argument("--privkey", default="private.pem")

    # Utilities
    hf = sub.add_parser("hash", help="Hash a file")
    hf.add_argument("input")

    sw = sub.add_parser("wipe", help="Securely wipe a file")
    sw.add_argument("input")
    sw.add_argument("--passes", type=int, default=3)

    # Menu
    sub.add_parser("menu", help="Launch interactive menu")

    if len(sys.argv) == 1:
        interactive_menu()
        return

    args = parser.parse_args()

    if args.cmd == "aes-encrypt":      aes_encrypt_file(args.input, args.output)
    elif args.cmd == "aes-decrypt":    aes_decrypt_file(args.input, args.output)
    elif args.cmd == "chacha-encrypt": chacha_encrypt_file(args.input, args.output)
    elif args.cmd == "chacha-decrypt": chacha_decrypt_file(args.input, args.output)
    elif args.cmd == "rsa-keygen":     generate_rsa_keypair(args.dir)
    elif args.cmd == "rsa-encrypt":    rsa_encrypt_file(args.input, args.pubkey)
    elif args.cmd == "rsa-decrypt":    rsa_decrypt_file(args.input, args.privkey)
    elif args.cmd == "hash":           hash_file(args.input)
    elif args.cmd == "wipe":           secure_wipe(args.input, args.passes)
    elif args.cmd == "menu":           interactive_menu()


if __name__ == "__main__":
    main()
