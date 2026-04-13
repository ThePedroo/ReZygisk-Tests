#!/usr/bin/env python3
"""
Signing tool for ReZygisk module.

Implements the same signing logic as the Gradle build:
  - machikado: per-architecture runtime file signatures
  - misaki: whole-module signature
  - sha256: per-file SHA-256 hashes
"""

import sys
import os
import struct
import hashlib
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def file_sign_data(name: str, filepath: str) -> bytes:
    """
    Build the sign data block for a single file, matching the Gradle sha() function:
      name_bytes + 0x00 + 8-byte-LE-filesize + file_contents
    """
    data = bytearray()
    data.extend(name.encode('utf-8'))
    data.append(0)
    size = os.path.getsize(filepath)
    data.extend(struct.pack('<q', size))
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            data.extend(chunk)
    return bytes(data)


def sign_machikado(module_dir: str, sig_name: str, abi: str, is_64bit: bool,
                   private_key_bytes: bytes, public_key_bytes: bytes):
    """
    Sign a machikado file for a specific architecture.

    The Gradle code creates virtual File objects for the "first" element of each pair
    and uses the "second" element (or first if null) for actual content.
    Pairs are sorted by first.path (full path), but only first.name (basename) is signed.
    """
    root = Path(module_dir)
    arch_suffix = "64" if is_64bit else "32"
    path_suffix = "lib64" if is_64bit else "lib"

    # Build the list of (virtual_path, virtual_name, real_file_path) triples
    # virtual_path is used for sorting, virtual_name is used in the signature,
    # real_file_path is used for content and size.
    entries = []

    # Files with no real override (real = virtual)
    for fname in ["module.prop", "rezygisk.sh", "sepolicy.rule", "post-fs-data.sh", "service.sh", "uninstall.sh"]:
        vpath = root / fname
        entries.append((str(vpath), fname, str(vpath)))

    # lib(64)/libzygisk.so -> lib/{abi}/libzygisk.so
    vpath = root / path_suffix / "libzygisk.so"
    rpath = root / "lib" / abi / "libzygisk.so"
    entries.append((str(vpath), "libzygisk.so", str(rpath)))

    # bin/zygisk-ptrace{32|64} -> lib/{abi}/libzygisk_ptrace.so
    vpath = root / "bin" / f"zygisk-ptrace{arch_suffix}"
    rpath = root / "lib" / abi / "libzygisk_ptrace.so"
    entries.append((str(vpath), f"zygisk-ptrace{arch_suffix}", str(rpath)))

    # bin/zygiskd{32|64} -> bin/{abi}/zygiskd
    vpath = root / "bin" / f"zygiskd{arch_suffix}"
    rpath = root / "bin" / abi / "zygiskd"
    entries.append((str(vpath), f"zygiskd{arch_suffix}", str(rpath)))

    # Sort by virtual path (with forward slashes, matching Java TreeSet behavior)
    entries.sort(key=lambda e: e[0].replace("\\", "/"))

    # Accumulate all sign data
    sign_data = bytearray()
    for _, vname, rpath in entries:
        sign_data.extend(file_sign_data(vname, rpath))

    # Sign with Ed25519
    priv_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    signature = priv_key.sign(bytes(sign_data))

    # Write signature + public key
    sig_file = root / sig_name
    with open(sig_file, 'wb') as f:
        f.write(signature)
        f.write(public_key_bytes)

    print(f"  Signed {sig_name}")


def compute_sha256_hashes(module_dir: str):
    """Compute SHA-256 hash for every file in the module directory."""
    root = Path(module_dir)
    for fpath in sorted(root.rglob('*')):
        if not fpath.is_file():
            continue
        # Don't hash .sha256 files themselves
        if fpath.suffix == '.sha256':
            continue
        md = hashlib.sha256()
        with open(fpath, 'rb') as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                md.update(chunk)
        hash_file = Path(str(fpath) + ".sha256")
        hash_file.write_text(md.hexdigest())


def sign_misaki(module_dir: str, private_key_bytes: bytes, public_key_bytes: bytes):
    """
    Sign misaki.sig for the entire module.
    Signs ALL files (sorted by full path) except misaki.sig itself.
    Uses basename as the name in the signature.
    """
    root = Path(module_dir)

    # Collect all files, sorted by path (with forward slashes)
    all_files = []
    for fpath in root.rglob('*'):
        if not fpath.is_file():
            continue
        if fpath.name == "misaki.sig":
            continue
        all_files.append(fpath)

    all_files.sort(key=lambda f: str(f).replace("\\", "/"))

    # Accumulate sign data
    sign_data = bytearray()
    for fpath in all_files:
        sign_data.extend(file_sign_data(fpath.name, str(fpath)))

    # Sign
    priv_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    signature = priv_key.sign(bytes(sign_data))

    sig_file = root / "misaki.sig"
    with open(sig_file, 'wb') as f:
        f.write(signature)
        f.write(public_key_bytes)

    print("  Signed misaki.sig")


def main():
    if len(sys.argv) < 3:
        print("Usage: sign.py <module_dir> <private_key> <public_key>")
        print("       sign.py --no-sign <module_dir>")
        sys.exit(1)

    if sys.argv[1] == "--no-sign":
        module_dir = sys.argv[2]
        root = Path(module_dir)

        print("No private_key found, this build will not be signed")

        # Create empty machikado files
        for name in ["machikado.arm64", "machikado.arm", "machikado.x86_64", "machikado.x86"]:
            (root / name).touch()

        # Compute SHA256 hashes
        compute_sha256_hashes(module_dir)

        # Create empty misaki.sig
        (root / "misaki.sig").touch()
        return

    module_dir = sys.argv[1]
    private_key_path = sys.argv[2]
    public_key_path = sys.argv[3]

    with open(private_key_path, 'rb') as f:
        private_key_bytes = f.read()
    with open(public_key_path, 'rb') as f:
        public_key_bytes = f.read()

    print("=== Guards the peace of Machikado ===")

    # Sign machikado for each architecture
    sign_machikado(module_dir, "machikado.arm64", "arm64-v8a", True,
                   private_key_bytes, public_key_bytes)
    sign_machikado(module_dir, "machikado.arm", "armeabi-v7a", False,
                   private_key_bytes, public_key_bytes)
    sign_machikado(module_dir, "machikado.x86_64", "x86_64", True,
                   private_key_bytes, public_key_bytes)
    sign_machikado(module_dir, "machikado.x86", "x86", False,
                   private_key_bytes, public_key_bytes)

    # Compute SHA256 hashes for all files (including machikado)
    compute_sha256_hashes(module_dir)

    print("===   At the kitsune's wedding   ===")

    # Sign misaki (signs everything including .sha256 files, excluding misaki.sig)
    sign_misaki(module_dir, private_key_bytes, public_key_bytes)


if __name__ == '__main__':
    main()
