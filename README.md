# xor-analyzer

> A tool for analyzing XOR-based encryption, including key recovery and ciphertext comparison for educational cryptography research.

---

## Overview

**xor-analyzer** is a simple Windows-friendly tool designed to:

-  Recover XOR encryption keys from reused-key ciphertexts
-  Compare encrypted files to detect key reuse patterns
-  Decrypt files once a key has been recovered
-  Demonstrate weaknesses in repeating-key XOR schemes

Intended as a learning aid for **SSCP / cybersecurity studies**, specifically illustrating the **key reuse vulnerability** in XOR-based encryption.

---

##  How It Works (Cryptography Concept)

When two files are encrypted with the **same XOR key**:

```
C1 = P1 XOR K
C2 = P2 XOR K

C1 XOR C2 = P1 XOR P2    ← key cancels completely
```

If the plaintexts share a known structure (like a file header), the key can be recovered with a **known-plaintext attack**:

```
Key = Ciphertext XOR KnownPlaintext
```

This tool automates both steps — from cancelling the key out of two ciphertexts, all the way to writing the decrypted file to disk.

---

## ⚙️ Requirements

- **Python 3.8+** installed and on your `PATH`
  → Download: https://www.python.org/downloads/
  → ✅ Tick **"Add Python to PATH"** during install

No third-party packages required — uses the Python standard library only.

---

## 🚀 Usage

Double-click `xor_tool.bat` to launch the menu, then choose an option.

### Option 1 — Key Recovery

*Use this when you have two files encrypted with the same key.*

1. Press `1` at the menu
2. Drag and drop **File 1** (first ciphertext) into the window → `Enter`
3. Drag and drop **File 2** (second ciphertext) into the window → `Enter`
4. The tool will automatically:
   - XOR the two ciphertexts together (cancelling the key)
   - Estimate the key length from zero-byte patterns
   - Test known file headers to derive the key (known-plaintext attack)
   - Validate candidates using structural checks beyond the header
   - Print the recovered key in hex

### Option 2 — Decrypt a File

*Use this once you have a key from Option 1.*

1. Press `2` at the menu
2. Drag and drop the **encrypted file** into the window → `Enter`
3. Paste the hex key (e.g. `02aaf8c6dcab4726efbb0098`) → `Enter`
4. The decrypted file is saved to the **same folder** as the input, with `_decrypted` added to the filename

---

##  Supported File Formats (Known-Plaintext Headers)

The tool tries the following known magic byte sequences for key recovery:

| Format            | Magic Bytes (hex)                                         |
|-------------------|-----------------------------------------------------------|
| Lua 5.1 bytecode  | `1B 4C 75 61 51 00 01 04 04 04 08 00`                     |
| Lua 5.2 bytecode  | `1B 4C 75 61 52`                                          |
| Lua 5.3 bytecode  | `1B 4C 75 61 53`                                          |
| Lua 5.4 bytecode  | `1B 4C 75 61 54`                                          |
| PNG image         | `89 50 4E 47 0D 0A 1A 0A`                                 |
| ZIP archive       | `50 4B 03 04`                                             |
| PDF document      | `25 50 44 46`                                             |
| XML / text        | `3C 3F 78 6D 6C`                                          |
| SQLite database   | `53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00`         |

To add more, open `xor_tool.py` and append entries to the `KNOWN_HEADERS` list.

---

## Example Output

```
File 1 : C:\files\Elsword_SwordMan.lua
File 2 : C:\files\RAVEN_FIGHTER.lua
Sizes  : 166,137 bytes / 136,011 bytes
Overlap: 136,011 bytes

──────────────────────────────────────────────────
STEP 1 — C1 XOR C2 = P1 XOR P2  (key cancels)
──────────────────────────────────────────────────
XOR result first 64 bytes : 000000000000000000000000...
Zero bytes in result      : 5,972 / 136,011  (4.4%)

[~] MODERATE zero % — possible key reuse (binary files naturally score lower).
    Proceeding with key recovery attempt...

──────────────────────────────────────────────────
STEP 3 — Known-plaintext key recovery
──────────────────────────────────────────────────
  Score  Format                     Key (hex)
  3.000  Lua 5.1 bytecode           02aaf8c6dcab4726efbb0098

[★] BEST KEY CANDIDATE
    Format : Lua 5.1 bytecode
    Key    : 02aaf8c6dcab4726efbb0098

STEP 4 — Verification (strings from decrypted File 1)
  @E:\hudson\jobs\ES_JP_SINGLE_CLIENT\workspace\...\Elsword_SwordMan.lua

==================================================
Key (hex) : 02aaf8c6dcab4726efbb0098
Key length: 12 bytes
==================================================
```

---

## Why This Matters (SSCP Context)

This attack breaks:

| Scheme | Why it's vulnerable |
|--------|---------------------|
| Repeating-key XOR | Key cycles — two ciphertexts with the same key cancel it out |
| WEP (Wi-Fi) | Uses RC4 with reused IVs — same mathematical weakness |
| One-time pad misuse | A OTP is only secure when the key is used **exactly once** |

**The fix:** never reuse a key. Use a modern authenticated cipher like **AES-GCM** or **ChaCha20-Poly1305**.

---

## Repository Structure

```
xor-analyzer/
├── xor_tool.bat    # Menu launcher — double-click to run (Windows)
├── xor_tool.py     # Key recovery and decryption logic (Python)
└── README.md       # This file
```

---

## 📜 License

MIT — free to use, modify, and share.
