"""
xor_tool.py -- XOR key recovery and decryption backend
Called by xor_tool.bat

Usage:
    python xor_tool.py compare <file1> <file2> [output.txt]
    python xor_tool.py decrypt <file> <hex_key> [output.txt]
"""

import sys
import os
import re

# ─── Output helper ────────────────────────────────────────────────────────────

_log_file = None

def log(text=""):
    """Print to console and write to output file if one is open."""
    print(text)
    if _log_file:
        _log_file.write(text + "\n")
        _log_file.flush()

def open_log(path):
    global _log_file
    _log_file = open(path, "w", encoding="utf-8")

def close_log():
    if _log_file:
        _log_file.close()

# ─── Known plaintext headers ──────────────────────────────────────────────────
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


def extract_strings(data: bytes, min_len: int = 6) -> list:
    return [m.group().decode("ascii") for m in re.finditer(rb'[ -~]{%d,}' % min_len, data)]


def guess_key_from_headers(ciphertext: bytes) -> list:
    results = []
    for label, header in KNOWN_HEADERS:
        n = min(len(header), len(ciphertext))
        if n < 4:
            continue
        candidate_key = bytes(ciphertext[i] ^ header[i] for i in range(n))
        results.append((label, candidate_key))
    return results


def score_key(ciphertext: bytes, key: bytes, sample: int = 512) -> float:
    decrypted = xor_decrypt(ciphertext[:sample], key)
    printable = sum(1 for b in decrypted if 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D))
    return printable / len(decrypted)


def detect_key_length(xored: bytes, max_len: int = 64) -> list:
    results = []
    for kl in range(1, min(max_len + 1, len(xored) // 4)):
        zero_count = sum(1 for i in range(0, len(xored), kl) if xored[i] == 0)
        score = zero_count / (len(xored) // kl + 1)
        results.append((kl, score))
    results.sort(key=lambda x: -x[1])
    return results[:10]


# ─── Mode 1: Compare ──────────────────────────────────────────────────────────

def mode_compare(file1: str, file2: str):
    from datetime import datetime

    log(f"Run        : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log(f"File 1     : {file1}")
    log(f"File 2     : {file2}")

    with open(file1, "rb") as f:
        ct1 = f.read()
    with open(file2, "rb") as f:
        ct2 = f.read()

    log(f"Sizes      : {len(ct1):,} bytes / {len(ct2):,} bytes")
    overlap = min(len(ct1), len(ct2))
    log(f"Overlap    : {overlap:,} bytes")
    log()

    # Step 1
    xored = bytes(ct1[i] ^ ct2[i] for i in range(overlap))
    zero_pct = 100 * xored.count(0) / overlap

    log("-" * 50)
    log("STEP 1 -- C1 XOR C2 = P1 XOR P2  (key cancels)")
    log("-" * 50)
    log(f"XOR first 64 bytes : {xored[:64].hex()}")
    log(f"Zero bytes         : {xored.count(0):,} / {overlap:,}  ({zero_pct:.1f}%)")

    if zero_pct > 10:
        log()
        log("[+] HIGH zero % -- files very likely share the SAME KEY.")
        log("    Key reuse confirmed. Proceeding to key recovery...")
    elif zero_pct > 2:
        log()
        log("[~] MODERATE zero % -- possible key reuse (binary files naturally score lower).")
        log("    Proceeding with key recovery attempt...")
    else:
        log()
        log("[!] Low zero % -- files may use different keys or plaintexts differ significantly.")
    log()

    # Step 2
    log("-" * 50)
    log("STEP 2 -- Candidate key lengths (by zero-byte pattern)")
    log("-" * 50)
    kl_candidates = detect_key_length(xored)
    log(f"{'Length':>8}  {'Score':>8}")
    for kl, score in kl_candidates[:8]:
        bar = "#" * int(score * 40)
        log(f"{kl:>8}  {score:>7.3f}  {bar}")
    best_kl = kl_candidates[0][0]
    log(f"\nBest guess: key length = {best_kl} bytes")
    log()

    # Step 3
    log("-" * 50)
    log("STEP 3 -- Known-plaintext key recovery")
    log("-" * 50)
    candidates = guess_key_from_headers(ct1)

    scored = []
    for label, raw_key in candidates:
        key = raw_key
        dec = xor_decrypt(ct1[:256], key)
        structural_score = 0.0

        if "Lua" in label and len(key) >= 5:
            if dec[16:17] == b'@':
                structural_score = 3.0
            elif b'\x00' in dec[17:80] and any(32 <= b < 127 for b in dec[17:50]):
                structural_score = 2.0
        elif "SQLite" in label and len(key) >= 16:
            page_size = int.from_bytes(dec[16:18], 'big')
            if page_size in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536):
                structural_score = 2.5
        elif "PNG" in label and len(key) >= 8:
            if dec[8:16] == bytes([0, 0, 0, 13, 73, 72, 68, 82]):
                structural_score = 2.5
        elif "ZIP" in label and len(key) >= 4:
            fname_len = int.from_bytes(dec[26:28], 'little') if len(dec) > 28 else 0
            if 1 <= fname_len <= 255:
                structural_score = 2.0

        if structural_score == 0.0:
            structural_score = score_key(ct1, key)

        scored.append((structural_score, label, key))

    scored.sort(reverse=True)

    log(f"{'Score':>7}  {'Format':<25}  Key (hex)")
    log("-" * 70)
    for sc, label, key in scored[:6]:
        log(f"{sc:>7.3f}  {label:<25}  {key.hex()}")

    best = scored[0]
    best_key = best[2]

    log()
    log("[*] BEST KEY CANDIDATE")
    log(f"    Format : {best[1]}")
    log(f"    Key    : {best_key.hex()}")
    log(f"    Score  : {best[0]:.3f}")
    log()

    # Step 4
    log("-" * 50)
    log("STEP 4 -- Verification (strings from decrypted File 1)")
    log("-" * 50)
    decrypted_preview = xor_decrypt(ct1[:4096], best_key)
    strings = extract_strings(decrypted_preview)
    if strings:
        for s in strings[:10]:
            log(f"  {s}")
    else:
        log("  (no long ASCII strings found -- plaintext may not be ASCII-heavy)")

    log()
    log("=" * 50)
    log("RESULT")
    log("=" * 50)
    log(f"Key (hex)  : {best_key.hex()}")
    log(f"Key length : {len(best_key)} bytes")
    log()
    log("Use this key in Option 2 to decrypt either file.")


# ─── Mode 2: Decrypt ──────────────────────────────────────────────────────────

def mode_decrypt(filepath: str, hex_key: str):
    from datetime import datetime

    hex_key = hex_key.strip().replace(" ", "").replace("0x", "")
    if not re.fullmatch(r'[0-9a-fA-F]+', hex_key):
        log(f"ERROR: Key must be hex digits only. Got: {hex_key!r}")
        sys.exit(1)
    if len(hex_key) % 2 != 0:
        log("ERROR: Key hex string must have an even number of characters.")
        sys.exit(1)

    key = bytes.fromhex(hex_key)

    log(f"Run        : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log(f"File       : {filepath}")
    log(f"Key (hex)  : {hex_key}")
    log(f"Key length : {len(key)} bytes")
    log()

    with open(filepath, "rb") as f:
        ciphertext = f.read()
    log(f"Read {len(ciphertext):,} bytes.")

    decrypted = xor_decrypt(ciphertext, key)

    base, ext = os.path.splitext(filepath)
    out_path = f"{base}_decrypted{ext}"

    with open(out_path, "wb") as f:
        f.write(decrypted)

    log()
    log("=" * 50)
    log("RESULT")
    log("=" * 50)
    log(f"Decrypted file saved to:")
    log(f"  {out_path}")
    log()

    strings = extract_strings(decrypted[:4096])
    if strings:
        log("Sample strings from decrypted output:")
        for s in strings[:8]:
            log(f"  {s}")
    else:
        log("(No long ASCII strings in first 4KB -- verify the key is correct.)")


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    mode = sys.argv[1].lower()

    if mode == "compare":
        if len(sys.argv) < 4:
            print("Usage: python xor_tool.py compare <file1> <file2> [output.txt]")
            sys.exit(1)
        if len(sys.argv) >= 5:
            open_log(sys.argv[4])
        mode_compare(sys.argv[2], sys.argv[3])
        close_log()

    elif mode == "decrypt":
        if len(sys.argv) < 4:
            print("Usage: python xor_tool.py decrypt <file> <hex_key> [output.txt]")
            sys.exit(1)
        if len(sys.argv) >= 5:
            open_log(sys.argv[4])
        mode_decrypt(sys.argv[2], sys.argv[3])
        close_log()

    else:
        print(f"Unknown mode: {mode!r}. Use 'compare' or 'decrypt'.")
        sys.exit(1)
