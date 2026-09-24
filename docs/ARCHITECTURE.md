# Architecture

## Pipeline

```
   Input binary
        │
        ▼
  ┌─────────────────┐
  │ introspection   │  file_info, security, imported_functions,
  │                 │  defined_functions, scan_strings
  └────────┬────────┘
           │
           ▼
  ┌─────────────────┐
  │ pattern_recon   │  get_disasm_blocks → find_main_candidate,
  │                 │  find_win_candidates (scoring heuristics)
  └────────┬────────┘
           │
           ▼
  ┌─────────────────┐
  │ decompile       │  angr → objdump fallback
  └────────┬────────┘
           │
           ▼
  ┌─────────────────┐
  │ classify_vulns  │  35+ templates scored by facts
  └────────┬────────┘
           │
     ┌─────┴─────┐
     ▼           ▼
  report     silent_auto_exploit
     │           │
     ▼           ▼
 decomp/*   solver.py (if win)
```

## Modules (single file)

| Function | Purpose |
|----------|---------|
| `decompile_angr` | angr-based C decompiler with fallback pseudocode |
| `decompile_objdump` | low-quality fallback when angr fails |
| `security` | checksec equivalent (readelf parsing) |
| `imported_functions` | 6-method import extraction |
| `defined_functions` | 4-method symbol recovery |
| `pattern_recon` | entry point for main/win heuristics |
| `find_main_candidate` | score functions by `__libc_start_main` ref |
| `find_win_candidates` | score functions by `/bin/sh`, `system`, etc. |
| `classify_vulns` | all vuln templates |
| `silent_auto_exploit` | tries templates quietly |
| `write_solver_skeleton` | rich starter template |
| `write_findings` | full report + payload templates |

## Adding a new vuln type

1. Add the API name to `DANGEROUS` dict.
2. Add a hint to `HINTS`.
3. In `classify_vulns()`, add a new block:
   ```python
   if condition:
       results.append({
           'name': 'my_new_vuln',
           'confidence': 'HIGH',
           'why': '...',
           'recipe': ['step1', 'step2'],
           'payload': '...',
       })
   ```
4. Optionally add auto-exploit in `silent_auto_exploit()`.

## Adding a new decompiler backend

1. Write `decompile_mytool(binary, funcs) -> str`.
2. Register in `decompile()` dispatcher order.
3. Update `detect_backends()`.

## Adding pattern recognition for another target

1. Write a scorer like `find_win_candidates` that returns `[(name, addr, score, reason)]`.
2. Call it from `pattern_recon()`.
3. Optionally merge candidates into `funcs_list` in `run()`.
