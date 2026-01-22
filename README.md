# Nattramn Binary Reverse Engineering

This repository documents the reverse engineering and payload extraction of the **Nattramn** binary, an SHC (Shell Script Compiler) compiled iOS device activation tool.

## Overview

| Property | Value |
|----------|-------|
| **Binary** | `Nattramn` |
| **Type** | Mach-O 64-bit executable x86_64 |
| **Packer** | SHC (Shell Script Compiler) |
| **Original Size** | 374,308 bytes |
| **Extracted Script** | 242,885 bytes (~9,200 lines) |

## Files

- `Nattramn` - Original compiled binary
- `nattramn_payload.sh` - Extracted bash script payload
- `cmdline_raw.txt` - Raw captured command line (reference)

---

## Decryption Process

### Step 1: Binary Analysis

Initial analysis revealed the binary is a **Mach-O 64-bit executable** compiled with **SHC (Shell Script Compiler)**:

```bash
$ file Nattramn
Nattramn: Mach-O 64-bit executable x86_64
```

Key indicators of SHC:
- Large `__DATA` segment (364,544 bytes) containing encrypted payload
- RC4 encryption routines in the `__TEXT` section
- Characteristic strings: "has expired!", "location has changed!"

### Step 2: Understanding SHC Structure

SHC compiles shell scripts into C code that:
1. Stores the script as RC4-encrypted data in the binary
2. At runtime, decrypts the script into memory
3. Executes via `execvp("/bin/bash", ["-c", <decrypted_script>])`

The encryption uses:
- **RC4 cipher** with multiple key scheduling passes
- **Key derived from**: binary code section + payload data
- **In-place decryption** of metadata sections

### Step 3: Static Analysis (Partial Success)

Disassembly revealed the RC4 decryption sequence:

```
Offset 0x58c26: 256-byte RC4 key
Offset 0x58d3e: Expiry message (65 bytes)
Offset 0x58bf3: Time check byte
Offset 0x58bcb: Shell path metadata
Offset 0x0b:    Main script (363,440 bytes)
```

Static decryption successfully recovered metadata:
- Shell: `/bin/bash`
- Args: `-c`
- Exec format: `exec '%s' "$@"`
- Expiry message: `has expired! Please contact your provider jahidulhamid@yahoo.com`

However, the main script decryption failed due to complex state-dependent hash verification.

### Step 4: Runtime Extraction (Success)

Since SHC passes the decrypted script as a command-line argument to bash, the payload can be captured at runtime:

```bash
# Run the binary in background
arch -x86_64 ./Nattramn &
PID=$!

# Capture the full command line (contains the script)
ps -p $PID -o args= > cmdline_raw.txt

# The script is passed after "-c" with \012 escape sequences for newlines
```

### Step 5: Decode Escape Sequences

The captured command line contains the script with octal escape sequences:

```python
import re

def decode_escapes(s):
    def replace_octal(match):
        return chr(int(match.group(1), 8))
    return re.sub(r'\\0([0-7]{2})', replace_octal, s)

with open('cmdline_raw.txt', 'r') as f:
    content = f.read()

# Find script after "-c" and decode
idx = content.find('-c')
script = content[idx+2:].lstrip()
decoded = decode_escapes(script)

with open('nattramn_payload.sh', 'w') as f:
    f.write(decoded)
```

---

## Extracted Payload Details

### Tool Information

- **Name**: Nattramn Activator
- **Purpose**: iOS device activation/bypass tool
- **Supported iOS**: 6 through 18
- **Platform**: macOS only
- **Developer Contact**: jahidulhamid@yahoo.com

### Remote Infrastructure

| Server | Purpose |
|--------|---------|
| `nattramn666.cloud` | Main server for updates, bootchains, exploits |
| `/macs_autorizados/` | Authorization/licensing |
| `/ch41n5/b00t/` | Bootchain files |
| `/utilidades/` | Utility downloads |

---

## ZIP Passwords

The script downloads and extracts various encrypted ZIP files. Here are the passwords:

### Password 1: `burzum9989SaNcTuM.`

**Variable**: `$Unzp`

**Used for**:
- Device bootchain files: `~/Library/.Bootchain/$version/$deviceid.zip`
- Signing keys: `~/Library/.Bootchain/dep/ref/keys.zip`
- Certificates: `~/Library/.Bootchain/dep/ref/certs.zip`
- MDM bypass: `~/Library/.Bootchain/dep/ref/mdm.zip`
- Boot files for iOS 7, 8, 11, 12, 14, 16, 17

### Password 2: `éamancha8989.`

**Variable**: `$Unzp2`

**Used for**:
- iPad CCDT files: `~/Library/.Bootchain/dep/ref/btlg/iPad/.CCDT.zip`
- Extracts to: `~/Library/Caches/com.apple.iTunes/iTunes/System/files/`

### Password 3: `burzum9989SaNcTuM.plpm`

**Variable**: `$Unzp3`

**Used for**:
- PurpleMode files: `~/Library/.Bootchain/PurpleMode/$replace.zip`

---

## Other Credentials

### SSH Access

The tool connects to jailbroken devices via SSH:

```bash
# Default iOS root password
Password: alpine

# SSH command used
./sshpass -p alpine ssh -oHostKeyAlgorithms=+ssh-rsa \
    -o StrictHostKeyChecking=no root@localhost -p 2222
```

---

## Technical Notes

### Why Static Decryption Failed

SHC's RC4 implementation includes:
1. Multiple KSA (Key Scheduling Algorithm) passes
2. In-place PRGA (Pseudo-Random Generation Algorithm) decryption
3. Hash verification that modifies RC4 state
4. The "location has changed!" check compares two decrypted hash values

When hashes don't match (indicating binary modification or incorrect state), the script decryption produces garbage.

### Why Runtime Extraction Works

SHC must eventually pass the plaintext script to `execvp()`. By capturing the process's command line arguments after decryption but before execution, we bypass all cryptographic complexity.

---

---

## Bonus: Shell Script Compiler Tool

Included is `shc-compile.py`, a Python script that compiles bash scripts into encrypted executables (similar to SHC).

### Usage

```bash
# Basic usage - creates script.sh.x
./shc-compile.py myscript.sh

# Specify output name
./shc-compile.py myscript.sh -o myprogram

# Set expiry date
./shc-compile.py myscript.sh -o myprogram -e 2025-12-31

# Custom expiry message
./shc-compile.py myscript.sh -e 2025-12-31 -m "License expired! Contact sales@example.com"

# Use different shell (zsh, sh, etc.)
./shc-compile.py myscript.sh -s /bin/zsh

# Verbose output
./shc-compile.py myscript.sh -v

# Keep generated C source for inspection
./shc-compile.py myscript.sh -k
```

### Options

| Option | Description |
|--------|-------------|
| `-o, --output` | Output binary name (default: `<script>.x`) |
| `-s, --shell` | Shell interpreter (default: `/bin/bash`) |
| `-e, --expiry` | Expiry date in `YYYY-MM-DD` format |
| `-m, --message` | Custom expiry message |
| `-k, --keep-source` | Keep generated C source file |
| `-v, --verbose` | Show detailed progress |

### How It Works

1. Reads the input shell script
2. Generates a random 256-byte RC4 encryption key
3. Encrypts the script using RC4
4. Generates C code containing the encrypted script and decryption routine
5. Compiles with `cc` and strips symbols
6. The resulting binary decrypts and executes the script at runtime

### Requirements

- Python 3.6+
- C compiler (`cc`/`clang`/`gcc`)
- macOS or Linux

---

## Disclaimer

This analysis is for educational and research purposes only. The extracted script is the intellectual property of its original author. This documentation is intended to demonstrate reverse engineering techniques on protected shell scripts.
