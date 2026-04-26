"""
xor_tool.py — XOR key recovery and decryption backend
Called by xor_tool.bat

Usage:
    python xor_tool.py compare <file1> <file2>
    python xor_tool.py decrypt <file> <hex_key>
"""

import sys
import os
import re

# ─── Known plaintext headers ──────────────────────────────────────────────────
# These are checked in order. Each entry: (label, bytes)
KNOWN_HEADERS = [
    ("Lua 5.1 bytecode",   bytes([0x1B, 0x4C, 0x75, 0x61, 0x51, 0x00, 0x01, 0x04, 0x04, 0x04, 0x08, 0x00])),
    ("Lua 5.2 bytecode",   bytes([0x1B, 0x4C, 0x75, 0x61, 0x52])),
    ("Lua 5.3 bytecode",   bytes([0x1B, 0x4C, 0x75, 0x61, 0x53])),
    ("Lua 5.4 bytecode",   bytes([0x1B, 0x4C, 0x75, 0x61, 0x54])),
    ("PNG image",          bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])),
    ("ZIP archive",        bytes([0x50, 0x4B, 0x03, 0x04])),
    ("PDF document",       bytes([0x25, 0x50, 0x44, 0x46])),
    ("XML / text",         b'<?xml'),
    ("SQLite database",    b'SQLite format 3\x00'),
]

# ─── Helpers ──────────────────────────────────────────────────────────────────

def xor_decrypt(data: bytes, key: bytes) -> bytes:
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))


def extract_strings(data: bytes, min_len: int = 6) -> list[str]:
    """Pull printable ASCII strings from binary data."""
    return [m.group().decode("ascii") for m in re.finditer(rb'[ -~]{%d,}' % min_len, data)]


def guess_key_from_headers(ciphertext: bytes) -> list[tuple[str, bytes]]:
    """Try known plaintext headers to derive candidate keys."""
    results = []
    for label, header in KNOWN_HEADERS:
        n = min(len(header), len(ciphertext))
        if n < 4:
            continue
        candidate_key = bytes(ciphertext[i] ^ header[i] for i in range(n))
        results.append((label, candidate_key))
    return results


def score_key(ciphertext: bytes, key: bytes, sample: int = 512) -> float:
    """Score a key by how much printable ASCII the decryption produces."""
    decrypted = xor_decrypt(ciphertext[:sample], key)
    printable = sum(1 for b in decrypted if 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D))
    return printable / len(decrypted)


def detect_key_length(xored: bytes, max_len: int = 64) -> list[tuple[int, float]]:
    """
    Use the Index of Coincidence on the XOR of two ciphertexts to guess key length.
    C1 XOR C2 = P1 XOR P2, and positions where P1==P2 give 0x00.
    Count zero bytes in every nth position.
    """
    results = []
    for kl in range(1, min(max_len + 1, len(xored) // 4)):
        zero_count = sum(1 for i in range(0, len(xored), kl) if xored[i] == 0)
        score = zero_count / (len(xored) // kl + 1)
        results.append((kl, score))
    results.sort(key=lambda x: -x[1])
    return results[:10]


# ─── Mode 1: Compare ──────────────────────────────────────────────────────────

def mode_compare(file1: str, file2: str):
    print(f"File 1 : {file1}")
    print(f"File 2 : {file2}")

    with open(file1, "rb") as f:
        ct1 = f.read()
    with open(file2, "rb") as f:
        ct2 = f.read()

    print(f"Sizes  : {len(ct1):,} bytes / {len(ct2):,} bytes")
    overlap = min(len(ct1), len(ct2))
    print(f"Overlap: {overlap:,} bytes\n")

    # ── Step 1: XOR the two ciphertexts ──────────────────────────────────────
    xored = bytes(ct1[i] ^ ct2[i] for i in range(overlap))
    zero_pct = 100 * xored.count(0) / overlap

    print("─" * 50)
    print("STEP 1 — C1 XOR C2 = P1 XOR P2  (key cancels)")
    print("─" * 50)
    print(f"XOR result first 64 bytes : {xored[:64].hex()}")
    print(f"Zero bytes in result      : {xored.count(0):,} / {overlap:,}  ({zero_pct:.1f}%)")

    # Binary files (e.g. Lua bytecode) naturally have few zeros; even 2-5% is meaningful.
    if zero_pct > 10:
        print("\n[✓] HIGH zero % — files very likely share the SAME KEY.")
        print("    Key reuse confirmed. Proceeding to key recovery...\n")
    elif zero_pct > 2:
        print("\n[~] MODERATE zero % — possible key reuse (binary files naturally score lower).")
        print("    Proceeding with key recovery attempt...\n")
    else:
        print("\n[!] Low zero % — files may use different keys, or plaintexts differ significantly.")

    # ── Step 2: Guess key length ──────────────────────────────────────────────
    print("─" * 50)
    print("STEP 2 — Candidate key lengths (by zero-byte pattern)")
    print("─" * 50)
    kl_candidates = detect_key_length(xored)
    print(f"{'Length':>8}  {'Score':>8}")
    for kl, score in kl_candidates[:8]:
        bar = "█" * int(score * 40)
        print(f"{kl:>8}  {score:>7.3f}  {bar}")
    best_kl = kl_candidates[0][0]
    print(f"\nBest guess: key length = {best_kl} bytes\n")

    # ── Step 3: Known-plaintext key recovery ─────────────────────────────────
    print("─" * 50)
    print("STEP 3 — Known-plaintext key recovery")
    print("─" * 50)
    candidates = guess_key_from_headers(ct1)

    scored = []
    for label, raw_key in candidates:
        key = raw_key
        dec = xor_decrypt(ct1[:256], key)

        # ── Tier 1: structural validation beyond the header ────────────────
        # These checks look at content AFTER the header to confirm the key is right.
        structural_score = 0.0

        # Lua bytecode: after 12-byte header, expect 4-byte int then '@' + path
        if "Lua" in label and len(key) >= 5:
            # '@' at offset 16 signals Lua source name
            if dec[16:17] == b'@':
                structural_score = 3.0
            # Also check for null-terminated string in a reasonable range
            elif b'\x00' in dec[17:80] and any(32 <= b < 127 for b in dec[17:50]):
                structural_score = 2.0

        # SQLite: page size field at offset 16 should be a power of 2 (512–65536)
        elif "SQLite" in label and len(key) >= 16:
            page_size = int.from_bytes(dec[16:18], 'big')
            if page_size in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536):
                structural_score = 2.5

        # PNG: IHDR chunk at offset 8 (length=0x0000000D, type=IHDR)
        elif "PNG" in label and len(key) >= 8:
            if dec[8:16] == bytes([0, 0, 0, 13, 73, 72, 68, 82]):
                structural_score = 2.5

        # ZIP: local file header signature at offset 0 already in header;
        # check for reasonable filename length at offset 26
        elif "ZIP" in label and len(key) >= 4:
            fname_len = int.from_bytes(dec[26:28], 'little') if len(dec) > 28 else 0
            if 1 <= fname_len <= 255:
                structural_score = 2.0

        # Fallback: printable-char heuristic
        if structural_score == 0.0:
            structural_score = score_key(ct1, key)

        scored.append((structural_score, label, key))

    scored.sort(reverse=True)

    print(f"{'Score':>7}  {'Format':<25}  Key (hex)")
    print("-" * 70)
    for sc, label, key in scored[:6]:
        print(f"{sc:>7.3f}  {label:<25}  {key.hex()}")

    best = scored[0]
    best_key = best[2]

    print(f"\n[★] BEST KEY CANDIDATE")
    print(f"    Format : {best[1]}")
    print(f"    Key    : {best_key.hex()}")
    print(f"    Score  : {best[0]:.3f} (fraction of printable bytes after decryption)\n")

    # ── Step 4: Quick verification ────────────────────────────────────────────
    print("─" * 50)
    print("STEP 4 — Verification (strings from decrypted File 1)")
    print("─" * 50)
    decrypted_preview = xor_decrypt(ct1[:4096], best_key)
    strings = extract_strings(decrypted_preview)
    if strings:
        for s in strings[:10]:
            print(f"  {s}")
    else:
        print("  (no long ASCII strings found — plaintext may not be ASCII-heavy)")

    print()
    print("=" * 50)
    print("RESULT")
    print("=" * 50)
    print(f"Key (hex) : {best_key.hex()}")
    print(f"Key length: {len(best_key)} bytes")
    print()
    print("Use this key in Option 2 to decrypt either file.")


# ─── Mode 2: Decrypt ──────────────────────────────────────────────────────────

def mode_decrypt(filepath: str, hex_key: str):
    # Validate hex key
    hex_key = hex_key.strip().replace(" ", "").replace("0x", "")
    if not re.fullmatch(r'[0-9a-fA-F]+', hex_key):
        print(f"ERROR: Key must be hex digits only. Got: {hex_key!r}")
        sys.exit(1)
    if len(hex_key) % 2 != 0:
        print("ERROR: Key hex string must have an even number of characters.")
        sys.exit(1)

    key = bytes.fromhex(hex_key)
    print(f"File      : {filepath}")
    print(f"Key (hex) : {hex_key}")
    print(f"Key length: {len(key)} bytes\n")

    with open(filepath, "rb") as f:
        ciphertext = f.read()
    print(f"Read {len(ciphertext):,} bytes.")

    decrypted = xor_decrypt(ciphertext, key)

    # Build output path: same folder, filename gets _decrypted suffix
    base, ext = os.path.splitext(filepath)
    out_path = f"{base}_decrypted{ext}"

    with open(out_path, "wb") as f:
        f.write(decrypted)

    print(f"Decrypted file saved to:\n  {out_path}\n")

    # Quick sanity check — show some strings
    strings = extract_strings(decrypted[:4096])
    if strings:
        print("Sample strings from decrypted output:")
        for s in strings[:8]:
            print(f"  {s}")
    else:
        print("(No long ASCII strings in first 4KB — verify the key is correct.)")


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    mode = sys.argv[1].lower()

    if mode == "compare":
        if len(sys.argv) < 4:
            print("Usage: python xor_tool.py compare <file1> <file2>")
            sys.exit(1)
        mode_compare(sys.argv[2], sys.argv[3])

    elif mode == "decrypt":
        if len(sys.argv) < 4:
            print("Usage: python xor_tool.py decrypt <file> <hex_key>")
            sys.exit(1)
        mode_decrypt(sys.argv[2], sys.argv[3])

    else:
        print(f"Unknown mode: {mode!r}. Use 'compare' or 'decrypt'.")
        sys.exit(1)
