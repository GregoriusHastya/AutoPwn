# chall_id

> **All-in-one binary exploitation toolkit** — auto-detect vulnerabilities, decompile with angr, suggest payloads, and even solve simple CTF challenges silently.

[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS-lightgrey.svg)]()

---

## Features

- 🔍 **Automatic vulnerability detection** — 35+ pwn classes (ret2win, ret2libc, fmtstr, heap, SROP, ret2csu, and more)
- 🧠 **angr-powered decompiler** — Ghidra-quality C with objdump fallback
- 🎯 **Pattern recognition** — finds `main` and `win` in **stripped binaries** via heuristics
- 💡 **Payload suggester** — prints ready-to-use exploit templates per vuln type
- 🤖 **Silent auto-exploit** — tries known templates in the background, writes `solver.py` on success
- 📁 **Per-function extraction** — every function saved as `<name>.txt` with suspicious lines marked `>>>`
- 📊 **Rich reports** — checksec, dangerous imports, interesting strings, mitigations all in one view
- 🧰 **No r2ghidra/Ghidra required** — pure Python + angr, works out of the box

---

## Quick Start

### 1. Install

```bash
git clone https://github.com/<your-username>/chall_id.git
cd chall_id
pip install -r requirements.txt
```

### 2. Run

```bash
python3 chall_id.py ./your_binary
```

That's it. You'll get a full report + `./decomp/` extraction + `solver.py` if it managed to solve it.

---

## Installation

### Requirements

- **Python 3.8+** (3.10–3.12 recommended; 3.13+ may have angr compatibility issues)
- **Linux** (Ubuntu 20.04+, Debian 11+, Kali, Arch) or **macOS**
- **~500 MB** of disk space for angr dependencies

### Step-by-step

```bash
# 1. Clone
git clone https://github.com/<your-username>/chall_id.git
cd chall_id

# 2. Create a virtualenv (recommended)
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. (Optional) Install ROPgadget for gadget detection
pip install ROPgadget

# 5. (Optional) Install angr for real decompilation
pip install angr
```

### System dependencies

```bash
# Ubuntu / Debian
sudo apt update
sudo apt install -y python3 python3-pip python3-venv binutils file gdb

# Arch
sudo pacman -S python python-pip binutils file gdb

# macOS
brew install python binutils file
```

---

## Usage

```bash
# Basic — analyze a binary
python3 chall_id.py ./chall

# Decompile specific functions
python3 chall_id.py ./chall -d main,win,check_flag

# Force a specific backend
python3 chall_id.py ./chall --backend angr
python3 chall_id.py ./chall --backend objdump

# Save full report
python3 chall_id.py ./chall -o report.txt

# Skip silent auto-exploit
python3 chall_id.py ./chall --no-autoexploit

# Interactive mode (prompts for everything)
python3 chall_id.py

# Show installed backends
python3 chall_id.py --list-backends

# Extract only from an existing decompile dump
python3 chall_id.py --extract-only saved_decompile.c
```

---

## Example Output

```
========================================================================
  FILE INFO
========================================================================
  Path     : ./bank
  Type     : ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
  Arch     : x86-64 (64-bit)
  PIE      : False   Stripped: False   Static: False

========================================================================
  SECURITY MITIGATIONS
========================================================================
  Canary   : enabled
  NX       : enabled
  PIE      : disabled
  RELRO    : Partial
  Fortify  : disabled
  Static   : disabled

========================================================================
  DANGEROUS IMPORTS
========================================================================
  gets            → OVERFLOW_CRITICAL
  printf          → FMT_STRING
  system          → CMD_EXEC

========================================================================
  INTERESTING FUNCTIONS
========================================================================
  0x4011a6      win
  0x4011bc      main

========================================================================
  PATTERN RECOGNITION (stripped mode)
========================================================================
  main candidate: main @ 0x4011bc (score 25)
         → passed to __libc_start_main by _start; calls input function
  win candidates:
    [ 30] 0x4011a6    win
         → symbol matches win-like; calls system(); references /bin/sh

========================================================================
  POSSIBLE VULNERABILITY TYPES  (3)
========================================================================

  [HIGH] ret2win_canary_fmt
         Why: win + canary + printf(fmt) + overflow input
         Recipe:
           - Sweep %1$p … %40$p → find canary (ends 00, > 4GB)
           - Build overflow: buf + canary + rbp + ret + win
           - Send overflow then exit
         Payload:
           # 1. leak canary
           io.sendlineafter(b"name: ", f"%{CANARY_OFF}$p".encode())
           ...

  [HIGH] fmtstr_got_overwrite
         Why: printf(fmt) + writable GOT + win()
         ...

  [MEDIUM] ret2libc
         Why: overflow + no canary + no PIE + pop rdi; ret
         ...

========================================================================
  DECOMPILED OUTPUT  (backend: angr)
========================================================================
unsigned int main(void)
{
    char v2[128];
    puts("=== [ MBPTL INTERNAL SERVICE ] ===");
    printf("[>] Name: ");
    gets(v2);
    printf("[*] Welcome, %s!\n", v2);
    return 0;
}

/* ==== __secret @ 0x4006c6 ==== */
int __secret(void)
{
    return system("/bin/sh");
}

[+] Extraction complete → ./decomp/
    main.txt  (2 suspicious)
    __secret.txt  (1 suspicious)
    _decompile_all.c
    _findings.txt
    _solver_skeleton.py

[+] solver.py written (template: ret2win_canary_fmt)
```

---

## Output Files

After running, `./decomp/` contains:

| File | Purpose |
|------|---------|
| `<func>.txt` | Per-function decompile, `>>>` marks suspicious lines |
| `_decompile_all.c` | Combined decompile for grepping |
| `_findings.txt` | Full report + payload templates |
| `_solver_skeleton.py` | Exploit starter with all detected facts filled in |
| `solver.py` | Auto-generated exploit (only if auto-exploit succeeded) |

---

## Detected Vulnerability Types

### Stack / Control-Flow
- `ret2win` — jump to a win function
- `ret2win_canary_fmt` — leak canary via format string
- `ret2win_canary_brute` — byte-by-byte canary brute force (fork)
- `ret2win_pie` — leak PIE base then ret2win
- `ret2libc` / `ret2libc_canary_fmt`
- `ret2csu` — control gadgets via `__libc_csu_init`
- `ret2dlresolve` — resolve `system` at runtime
- `ret2plt` — call PLT stubs directly
- `partial_overwrite` — ASLR-defeat by overwriting low bytes
- `SROP` — sigreturn-oriented programming
- `one_gadget` — libc one-gadget magic

### Format String
- `fmtstr_got_overwrite`
- `fmtstr_arbitrary_write`
- `fmtstr_leak_only` — for canary / libc / PIE leak

### Shellcode
- `shellcode_stack` — NX disabled
- `mprotect_shellcode` — RWX via mprotect

### Heap
- `heap_uaf`
- `heap_double_free`
- `heap_tcache_poison`

### Misc
- `integer_overflow`
- `off_by_one`
- `oob_array`
- `command_injection`
- `race_condition`

---

## Architecture

```
┌─────────────────┐
│  Input binary   │
└────────┬────────┘
         │
         ▼
┌─────────────────────────┐
│   Introspection         │  → file, checksec, symbols, imports, strings
└────────┬────────────────┘
         │
         ▼
┌─────────────────────────┐
│  Pattern Recognition    │  → main candidate, win candidates (heuristics)
└────────┬────────────────┘
         │
         ▼
┌─────────────────────────┐
│  angr Decompiler        │  → Ghidra-quality C per function
│   (+ objdump fallback)  │
└────────┬────────────────┘
         │
         ▼
┌─────────────────────────┐
│  Vuln Classifier        │  → 35+ patterns scored per binary
└────────┬────────────────┘
         │
         ├──────────────────────────┐
         ▼                          ▼
┌─────────────────┐    ┌───────────────────────┐
│  Report + Files │    │  Silent Auto-Exploit  │
│  ./decomp/*     │    │  → solver.py (if win) │
└─────────────────┘    └───────────────────────┘
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for full details.

---

## Frequently Asked Questions

### Does it work on stripped binaries?

Yes. Pattern recognition (`find_win_candidates`, `find_main_candidate`) uses heuristics:
- Win = calls `system`/`execve`, references `/bin/sh`, is small, isn't called by anyone
- Main = referenced by `_start` through `__libc_start_main`, calls input functions

### Does it work on 32-bit binaries?

Partially. angr supports i386, and the pattern recognition is arch-agnostic. The silent auto-exploit templates focus on x86-64 but detection works on both.

### Can it solve heap challenges?

It **detects** heap primitives (UAF, double-free, tcache) but doesn't auto-exploit them — heap exploits require per-challenge logic.

### Why does angr fail on some functions?

angr's decompiler requires "normalized function graphs." When it fails, the script falls back to per-basic-block pseudocode so you still get something useful.

### Why no Ghidra / r2ghidra?

Those require either a heavy install (Ghidra ~500 MB, Java 21) or a fragile compile (r2ghidra vs radare2 version mismatch). angr is pure Python and installs with `pip`. If you want to add Ghidra support, see `docs/ARCHITECTURE.md` for the extension point.

### It said "no known vuln patterns detected" — what now?

Paste the `decomp/*.txt` output in an issue. The pattern set is extensive but not exhaustive; custom `copy()` functions or unusual primitives won't match.

---

## Roadmap

- [ ] Add `--remote HOST:PORT` for remote testing of auto-exploit
- [ ] Add `--dynamic` mode (runs binary under gdb + cyclic → auto offset)
- [ ] Add FLIRT-style signature detection
- [ ] Add `--emit-pwntools-project` (dump everything as a pwntools script)
- [ ] Add more auto-exploit templates (ret2libc, fmtstr GOT overwrite)
- [ ] Support 32-bit auto-exploit templates
- [ ] Add `--docker` mode for reproducible environments

---

## Contributing

Contributions welcome! See [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md).

Areas where help is especially appreciated:
- New vuln detection signatures
- More auto-exploit templates
- 32-bit / ARM support
- Test binaries + expected outputs

---

## License

MIT — see [`LICENSE`](LICENSE).

---

## Acknowledgements

- [angr](https://angr.io/) — symbolic execution + decompiler
- [pwntools](https://github.com/Gallopsled/pwntools) — CTF exploitation framework
- [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) — gadget finder
- Inspired by [Ghidra](https://ghidra-sre.org/), [radare2](https://rada.re/), [checksec](https://github.com/slimm609/checksec.sh)

---

## Legal

This tool is for **authorized security testing, CTF challenges, and educational purposes only**. Do not use it on systems you don't own or have explicit permission to test. The authors are not responsible for misuse.

---

**Star ⭐ this repo if it helps you!**
