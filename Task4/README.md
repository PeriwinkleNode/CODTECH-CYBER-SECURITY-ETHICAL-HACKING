# 🔐 Advanced Encryption Tool

A robust, Python-based encryption application supporting AES-256-GCM, ChaCha20-Poly1305, and RSA-2048 hybrid encryption. Includes file encryption, text encryption, RSA key generation, file hashing, and secure file wiping — all via an interactive menu or CLI flags.

---

## Features

- 🔒 **AES-256-GCM** — Industry-standard symmetric file encryption
- ⚡ **ChaCha20-Poly1305** — Modern stream cipher, faster on ARM/mobile
- 🗝️ **RSA-2048 Hybrid** — Asymmetric encryption (encrypt with public key, decrypt with private key)
- 📝 **Text Encryption** — Encrypt short strings to portable Base64 output
- #️⃣ **File Hashing** — MD5, SHA-1, SHA-256, SHA-512
- 🗑️ **Secure File Wipe** — Multi-pass random overwrite before deletion
- 🔑 **Scrypt Key Derivation** — High-strength password-to-key derivation (N=2¹⁷)
- 🖥️ **Interactive Menu** — User-friendly numbered interface

---

## Requirements

- Python 3.10+
- `cryptography`

---

## Installation

```bash
git clone https://github.com/yourusername/encryption-tool.git
cd encryption-tool
pip install cryptography
```

---

## Usage

### Interactive Menu (recommended)

```bash
python encryption_tool.py
```

Launches a numbered menu — no flags needed.

### CLI Mode

```bash
python encryption_tool.py <command> [arguments] [options]
```

---

## Commands

| Command | Description |
|---------|-------------|
| `aes-encrypt <file>` | AES-256-GCM encrypt a file |
| `aes-decrypt <file>` | AES-256-GCM decrypt a file |
| `chacha-encrypt <file>` | ChaCha20-Poly1305 encrypt a file |
| `chacha-decrypt <file>` | ChaCha20-Poly1305 decrypt a file |
| `rsa-keygen` | Generate RSA-2048 key pair |
| `rsa-encrypt <file>` | Encrypt file with RSA public key |
| `rsa-decrypt <file>` | Decrypt file with RSA private key |
| `hash <file>` | Hash a file (all 4 algorithms) |
| `wipe <file>` | Securely wipe a file |
| `menu` | Launch interactive menu |

---

## Testing

### Step 1 — Install dependency

```bash
pip install cryptography
```

### Step 2 — Create a test file

```bash
echo "This is my secret data" > secret.txt
```

---

### Test AES-256-GCM Encryption

```bash
# Encrypt
python encryption_tool.py aes-encrypt secret.txt

# Decrypt
python encryption_tool.py aes-decrypt secret.txt.enc --output recovered.txt

# Verify contents match
cat recovered.txt
# Expected: This is my secret data
```

---

### Test ChaCha20-Poly1305 Encryption

```bash
# Encrypt
python encryption_tool.py chacha-encrypt secret.txt

# Decrypt
python encryption_tool.py chacha-decrypt secret.txt.enc --output recovered2.txt

# Verify
cat recovered2.txt
# Expected: This is my secret data
```

---

### Test RSA-2048 Asymmetric Encryption

```bash
# Step 1: Generate a key pair (creates public.pem and private.pem)
python encryption_tool.py rsa-keygen

# Step 2: Encrypt the file using the public key
python encryption_tool.py rsa-encrypt secret.txt --pubkey public.pem

# Step 3: Decrypt using the private key
python encryption_tool.py rsa-decrypt secret.txt.rsa.enc --privkey private.pem

# Verify
cat secret.txt.dec
# Expected: This is my secret data
```

---

### Test Text Encryption (via Interactive Menu)

```bash
python encryption_tool.py menu
# Select option 5 (Encrypt text)
# Type: Hello, World!
# Enter a password
# Copy the Base64 output

# Then select option 6 (Decrypt text)
# Paste the Base64 string
# Enter the same password
# Expected output: Hello, World!
```

---

### Test File Hashing

```bash
python encryption_tool.py hash secret.txt
```

Expected output:
```
  MD5       : 5eb63bbbe01eeed093cb22bb8f5acdc3
  SHA-1     : 2aae6c69822a3b6b6b1d5e9c75a09e6b...
  SHA-256   : b94d27b9934d3e08a52e52d7da7dabfa...
  SHA-512   : 309ecc489c12d6eb4cc40f50c902f2b4...
```

---

### Test Secure File Wipe

```bash
# Create a throwaway file first
echo "delete me safely" > throwaway.txt

# Wipe it (3 passes of random data, then delete)
python encryption_tool.py wipe throwaway.txt --passes 3

# Verify it's gone
ls throwaway.txt
# Expected: No such file or directory
```

---

### Test Wrong Password (error handling)

```bash
# Encrypt with one password
python encryption_tool.py aes-encrypt secret.txt
# Enter password: correctpassword

# Try to decrypt with wrong password
python encryption_tool.py aes-decrypt secret.txt.enc
# Enter password: wrongpassword

# Expected:
# ✘  Decryption failed — wrong password or file is corrupted.
```

---

### Test Custom Output Path

```bash
python encryption_tool.py aes-encrypt secret.txt --output /tmp/my_encrypted_file.enc
python encryption_tool.py aes-decrypt /tmp/my_encrypted_file.enc --output /tmp/decrypted.txt
cat /tmp/decrypted.txt
```

---

## Encryption Details

| Algorithm | Type | Key Size | Mode | KDF |
|-----------|------|----------|------|-----|
| AES-256-GCM | Symmetric | 256-bit | GCM (authenticated) | Scrypt N=2¹⁷ |
| ChaCha20-Poly1305 | Symmetric | 256-bit | Stream + MAC | Scrypt N=2¹⁷ |
| RSA-2048 | Asymmetric | 2048-bit | OAEP-SHA256 | N/A |
| RSA Hybrid | Hybrid | 2048-bit RSA + 256-bit AES | OAEP + GCM | N/A |

---

## File Format

Encrypted files use a binary header to store all parameters needed for decryption:

### AES / ChaCha20 (password-based)
```
[4-byte magic][32-byte salt][12-byte nonce][ciphertext + auth tag]
```

### RSA Hybrid
```
[4-byte magic][2-byte key_len][RSA-encrypted session key][12-byte nonce][ciphertext]
```

---

## Security Notes

- Passwords are never stored — only a derived key is used
- Each encryption generates a unique random salt and nonce
- GCM and Poly1305 provide **authenticated encryption** — any tampering is detected
- RSA private keys can be password-protected during generation
- Secure wipe uses `os.urandom()` + `fsync()` for each pass

---

## License

MIT License — free to use and modify.
