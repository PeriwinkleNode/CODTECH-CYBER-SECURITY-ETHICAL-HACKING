#!/usr/bin/env python3
"""
File Integrity Checker
Monitors changes in files by calculating and comparing hash values using hashlib.
"""

import hashlib
import json
import os
import sys
import argparse
from datetime import datetime
from pathlib import Path


HASH_STORE_FILE = ".integrity_hashes.json"


def calculate_hash(filepath: str, algorithm: str = "sha256") -> str:
    """Calculate the hash of a file using the specified algorithm."""
    h = hashlib.new(algorithm)
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except (IOError, OSError) as e:
        print(f"  [ERROR] Cannot read '{filepath}': {e}")
        return None


def load_hash_store(store_path: str) -> dict:
    """Load existing hash records from the JSON store."""
    if os.path.exists(store_path):
        with open(store_path, "r") as f:
            return json.load(f)
    return {}


def save_hash_store(store_path: str, data: dict):
    """Save hash records to the JSON store."""
    with open(store_path, "w") as f:
        json.dump(data, f, indent=2)


def collect_files(targets: list) -> list:
    """Collect all file paths from the given targets (files or directories)."""
    files = []
    for target in targets:
        path = Path(target)
        if path.is_file():
            files.append(str(path.resolve()))
        elif path.is_dir():
            for fp in path.rglob("*"):
                if fp.is_file() and fp.name != HASH_STORE_FILE:
                    files.append(str(fp.resolve()))
        else:
            print(f"  [WARN] '{target}' does not exist — skipping.")
    return sorted(set(files))


def cmd_init(targets: list, algorithm: str, store_path: str):
    """Baseline: compute and store hashes for all target files."""
    print(f"\n{'='*55}")
    print(f"  INITIALIZING BASELINE  [{algorithm.upper()}]")
    print(f"{'='*55}")

    store = load_hash_store(store_path)
    files = collect_files(targets)

    if not files:
        print("  No files found.")
        return

    added = 0
    for fp in files:
        digest = calculate_hash(fp, algorithm)
        if digest:
            store[fp] = {
                "hash": digest,
                "algorithm": algorithm,
                "last_checked": datetime.now().isoformat(),
                "size": os.path.getsize(fp),
            }
            print(f"  [STORED]  {fp}")
            added += 1

    save_hash_store(store_path, store)
    print(f"\n  ✔ Baseline created for {added} file(s). Store: '{store_path}'\n")


def cmd_check(targets: list, store_path: str):
    """Check files against stored hashes and report any changes."""
    print(f"\n{'='*55}")
    print("  INTEGRITY CHECK")
    print(f"{'='*55}")

    store = load_hash_store(store_path)
    if not store:
        print("  [ERROR] No baseline found. Run with --init first.\n")
        sys.exit(1)

    files = collect_files(targets) if targets else list(store.keys())

    ok = modified = missing = new_files = 0

    for fp in files:
        if not os.path.exists(fp):
            print(f"  [MISSING]   {fp}")
            missing += 1
            continue

        if fp not in store:
            print(f"  [NEW/UNTRACKED] {fp}")
            new_files += 1
            continue

        record = store[fp]
        current_hash = calculate_hash(fp, record["algorithm"])
        if current_hash is None:
            continue

        if current_hash == record["hash"]:
            print(f"  [OK]        {fp}")
            ok += 1
        else:
            current_size = os.path.getsize(fp)
            print(f"  [MODIFIED]  {fp}")
            print(f"              Expected : {record['hash']}")
            print(f"              Got      : {current_hash}")
            print(f"              Size     : {record['size']} → {current_size} bytes")
            modified += 1

        # Update last_checked timestamp
        store[fp]["last_checked"] = datetime.now().isoformat()

    save_hash_store(store_path, store)

    print(f"\n{'─'*55}")
    print(f"  Results  →  OK: {ok}  |  Modified: {modified}  |  Missing: {missing}  |  New: {new_files}")
    print(f"{'─'*55}\n")

    if modified or missing:
        sys.exit(2)   # Non-zero exit so CI pipelines can detect tampering


def cmd_update(targets: list, store_path: str, algorithm: str):
    """Re-hash files and update their records in the store."""
    print(f"\n{'='*55}")
    print("  UPDATING HASHES")
    print(f"{'='*55}")

    store = load_hash_store(store_path)
    files = collect_files(targets)

    updated = 0
    for fp in files:
        algo = store.get(fp, {}).get("algorithm", algorithm)
        digest = calculate_hash(fp, algo)
        if digest:
            store[fp] = {
                "hash": digest,
                "algorithm": algo,
                "last_checked": datetime.now().isoformat(),
                "size": os.path.getsize(fp),
            }
            print(f"  [UPDATED]  {fp}")
            updated += 1

    save_hash_store(store_path, store)
    print(f"\n  ✔ Updated {updated} file(s).\n")


def cmd_list(store_path: str):
    """List all tracked files and their stored metadata."""
    store = load_hash_store(store_path)
    if not store:
        print("  No tracked files found.\n")
        return

    print(f"\n{'='*55}")
    print(f"  TRACKED FILES  ({len(store)} total)")
    print(f"{'='*55}")
    for fp, meta in store.items():
        exists = "✔" if os.path.exists(fp) else "✘ MISSING"
        print(f"\n  File      : {fp}")
        print(f"  Hash      : {meta['hash']}  [{meta['algorithm'].upper()}]")
        print(f"  Size      : {meta['size']} bytes")
        print(f"  Checked   : {meta['last_checked']}")
        print(f"  On disk   : {exists}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="File Integrity Checker — monitor files via hash comparison.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "command",
        choices=["init", "check", "update", "list"],
        help=(
            "init   – create baseline hashes\n"
            "check  – verify files against baseline\n"
            "update – refresh stored hashes\n"
            "list   – show all tracked files"
        ),
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="Files or directories to process (not needed for 'list').",
    )
    parser.add_argument(
        "--algo",
        default="sha256",
        choices=hashlib.algorithms_guaranteed,
        help="Hash algorithm to use (default: sha256).",
    )
    parser.add_argument(
        "--store",
        default=HASH_STORE_FILE,
        help=f"Path to the hash store JSON file (default: {HASH_STORE_FILE}).",
    )

    args = parser.parse_args()

    if args.command == "init":
        if not args.targets:
            parser.error("'init' requires at least one file or directory.")
        cmd_init(args.targets, args.algo, args.store)

    elif args.command == "check":
        cmd_check(args.targets, args.store)

    elif args.command == "update":
        if not args.targets:
            parser.error("'update' requires at least one file or directory.")
        cmd_update(args.targets, args.store, args.algo)

    elif args.command == "list":
        cmd_list(args.store)


if __name__ == "__main__":
    main()
