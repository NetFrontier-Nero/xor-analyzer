# xor-analyzer
Tool for analyzing XOR-based encryption, including key recovery and ciphertext comparison for educational cryptography research.

XOR Key Recovery Tool
A simple drag-and-drop Windows tool for recovering XOR encryption keys from reused-key ciphertexts, and decrypting files with a known key.
Built as a learning aid for SSCP / cryptography studies — specifically illustrating the key reuse vulnerability in repeating-key XOR schemes.

How It Works (The Crypto)
When two files are encrypted with the same XOR key:
C1 = P1 XOR K
C2 = P2 XOR K

C1 XOR C2 = P1 XOR P2    ← key cancels completely
If the plaintexts share a known structure (like a file header), you can recover the key with a known-plaintext attack:
Key = Ciphertext XOR KnownPlaintext
This tool automates both steps.

Requirements

Python 3.8+ must be installed and on your PATH
Download: https://www.python.org/downloads/
✅ Tick "Add Python to PATH" during install

No third-party packages needed — only the Python standard library.

Usage
Option 1 — Key Recovery (two ciphertexts)

Double-click xor_tool.bat
Press 1
Drag and drop the first encrypted file → Enter
Drag and drop the second encrypted file → Enter
The tool will:

XOR the files together (key cancels)
Estimate the key length
Try known-plaintext headers to derive the key
Show you the recovered key in hex

Option 2 — Decrypt a file

Double-click xor_tool.bat
Press 2
Drag and drop the encrypted file → Enter
Paste the hex key recovered from Option 1 → Enter
The decrypted file is saved in the same folder as the input, with _decrypted appended to the filename

Known Plaintext Headers Supported
The tool automatically tries these known file headers for key recovery:
FormatMagic bytesLua 5.1 bytecode1B 4C 75 61 51 00 01 04 04 04 08 00Lua 5.2 bytecode1B 4C 75 61 52Lua 5.3 bytecode1B 4C 75 61 53Lua 5.4 bytecode1B 4C 75 61 54PNG image89 50 4E 47 0D 0A 1A 0AZIP archive50 4B 03 04PDF document25 50 44 46XML / text3C 3F 78 6D 6CSQLite database53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00
Add more headers in xor_tool.py under KNOWN_HEADERS as needed.

Example Output (Option 1)
File 1 : C:\files\Els_SwordMan.lua
File 2 : C:\files\RAV_FIGHTER.lua
Sizes  : 166,137 bytes / 136,011 bytes
Overlap: 136,011 bytes

──────────────────────────────────────────────────
STEP 1 — C1 XOR C2 = P1 XOR P2  (key cancels)
──────────────────────────────────────────────────
XOR result first 64 bytes : 000000000000000000000000...
Zero bytes in result      : 5,972 / 136,011  (4.4%)

[✓] HIGH zero % — files share the SAME KEY and similar structure.

STEP 3 — Known-plaintext key recovery
──────────────────────────────────────────────────
  Score  Format                     Key (hex)
  0.821  Lua 5.1 bytecode           02aaf8c6dcab4726efbb0098

[★] BEST KEY CANDIDATE
    Key : 02aaf8c6dcab4726efbb0098

Why This Matters (SSCP Context)
This attack breaks:

Any repeating-key XOR obfuscation (common in game engines, old malware)
WEP (uses RC4 with reused IVs — same mathematical weakness)
One-time pad misuse (a OTP is only secure if the key is used exactly once)

The fix: never reuse a key. Use a proper authenticated cipher (AES-GCM, ChaCha20-Poly1305).

Files
xor_tool.bat    — Menu launcher (Windows batch)
xor_tool.py     — Key recovery and decryption logic (Python)
README.md       — This file

License
MIT — free to use, modify, and share.
