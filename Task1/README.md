# 🔒 File Integrity Checker

A Python tool to monitor file changes by calculating and comparing cryptographic hash values. Detects tampering, corruption, or unauthorized modifications to files and directories.

---

## Features

- ✅ Supports all `hashlib` algorithms (`sha256`, `sha512`, `md5`, etc.)
- ✅ Scans individual files **or entire directories** recursively
- ✅ Stores hashes, file sizes, and timestamps in a JSON store
- ✅ Clearly reports `[OK]`, `[MODIFIED]`, `[MISSING]`, and `[NEW/UNTRACKED]` files
- ✅ Exits with code `2` when tampering is detected (CI/CD pipeline friendly)
- ✅ No third-party dependencies — pure Python standard library

---

## Requirements

- Python 3.10+
- No external libraries needed

---

## Installation

```bash
git clone https://github.com/yourusername/file-integrity-checker.git
cd file-integrity-checker
```

No installation required. Run directly with Python.

---

## Usage

```bash
python file_integrity_checker.py <command> [targets] [options]
```

### Commands

| Command | Description |
|---------|-------------|
| `init`   | Create a baseline of hashes for files/directories |
| `check`  | Verify files against the stored baseline |
| `update` | Re-hash files after intentional changes |
| `list`   | Show all tracked files and their metadata |

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--algo` | `sha256` | Hash algorithm to use |
| `--store` | `.integrity_hashes.json` | Path to the hash store file |

---

## Examples

```bash
# Create a baseline for a directory
python file_integrity_checker.py init ./my_folder

# Check files for changes
python file_integrity_checker.py check ./my_folder

# Use SHA-512 instead of SHA-256
python file_integrity_checker.py init ./my_folder --algo sha512

# Use a custom store file location
python file_integrity_checker.py init ./my_folder --store /secure/hashes.json

# Update hashes after intentional changes
python file_integrity_checker.py update ./my_folder/file.txt

# List all tracked files
python file_integrity_checker.py list
```

---

## Testing

### Step 1 — Create test files

```bash
mkdir test_files
echo "Hello World" > test_files/file1.txt
echo "Sensitive Data" > test_files/file2.txt
```

### Step 2 — Create a baseline

```bash
python file_integrity_checker.py init test_files/
```

Expected output: `[STORED]` for each file.

### Step 3 — Run a clean check

```bash
python file_integrity_checker.py check test_files/
```

Expected output: `[OK]` for all files.

### Step 4 — Simulate tampering

```bash
echo "Hacked content" > test_files/file1.txt
python file_integrity_checker.py check test_files/
```

Expected output: `[MODIFIED]` for `file1.txt` with old and new hash printed.

### Step 5 — Simulate a missing file

```bash
rm test_files/file2.txt
python file_integrity_checker.py check test_files/
```

Expected output: `[MISSING]` for `file2.txt`.

### Step 6 — Simulate a new untracked file

```bash
echo "New file" > test_files/file3.txt
python file_integrity_checker.py check test_files/
```

Expected output: `[NEW/UNTRACKED]` for `file3.txt`.

### Step 7 — List all tracked files

```bash
python file_integrity_checker.py list
```

### Step 8 — Update hashes after intentional changes

```bash
python file_integrity_checker.py update test_files/file1.txt
python file_integrity_checker.py check test_files/file1.txt
# Should show [OK] again
```

### Step 9 — Try a different hash algorithm

```bash
python file_integrity_checker.py init test_files/ --algo sha512
```

---

## Output Format

```
  [OK]        /path/to/file.txt
  [MODIFIED]  /path/to/changed.txt
              Expected : abc123...
              Got      : def456...
              Size     : 1024 → 2048 bytes
  [MISSING]   /path/to/deleted.txt
  [NEW/UNTRACKED] /path/to/newfile.txt
```

---

## Hash Store Format

Hashes are stored in `.integrity_hashes.json`:

```json
{
  "/absolute/path/to/file.txt": {
    "hash": "abc123...",
    "algorithm": "sha256",
    "last_checked": "2026-04-19T12:00:00",
    "size": 1024
  }
}
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | All files OK |
| `2` | Modified or missing files detected |

---

## License

MIT License — free to use and modify.
