#!/usr/bin/env python3
"""
kernel_bug_hunter.py
====================
Analiza ficheros del kernel Linux con Ollama (DeepSeek-Coder-V2:16b)
para encontrar bugs explotables sin privilegios.

Diseñado para minimizar falsos positivos:
  - Análisis en dos pasadas (detección → verificación)
  - Criterios estrictos de explotabilidad (kernelCTF-oriented)
  - Correlación con crashes existentes de syzkaller
  - Output estructurado con nivel de confianza

Uso:
  python3 kernel_bug_hunter.py --file net/ipv6/calipso.c
  python3 kernel_bug_hunter.py --dir net/ipv6/
  python3 kernel_bug_hunter.py --crashes ~/Work/LinuxScan/output/syzkaller_workdir/crashes
  python3 kernel_bug_hunter.py --diff v6.12.84..v6.12.85 --kernel ~/Work/LinuxScan/linux
  python3 kernel_bug_hunter.py --dir net/ --model deepseek-coder-v2:16b --output bugs.json

  Creador: y2k - Email: y2k@desarrollaria.com
"""

import os, sys, json, argparse, re, subprocess, time
from pathlib import Path
from datetime import datetime

# ── Configuración ──────────────────────────────────────────────────────────────
DEFAULT_MODEL   = 'deepseek-coder-v2:16b'
OLLAMA_URL      = 'http://localhost:11434'
WORK_DIR        = Path.home() / 'Work' / 'LinuxScan'
CRASHES_DIR     = WORK_DIR / 'output' / 'syzkaller_workdir' / 'crashes'
KERNEL_DIR      = WORK_DIR / 'linux'
OUTPUT_DIR      = WORK_DIR / 'output' / 'bug_analysis'

# Subsistemas de interés — accesibles sin CAP_* en kernelCTF
PRIORITY_SUBSYSTEMS = [
    'net/ipv6', 'net/ipv4', 'net/core', 'net/unix',
    'net/netfilter', 'net/packet', 'net/tipc',
    'fs/ext4', 'fs/btrfs', 'fs/overlayfs', 'fs/fuse',
    'ipc/', 'mm/', 'kernel/bpf', 'kernel/events',
    'security/selinux', 'security/smack',
]

# Patrones de bugs que interesan — triggereables sin privilegios
BUG_PATTERNS = [
    r'kfree\s*\(',
    r'kmem_cache_free\s*\(',
    r'refcount_dec\s*\(',
    r'atomic_dec_and_test\s*\(',
    r'list_del\s*\(',
    r'hlist_del\s*\(',
    r'rb_erase\s*\(',
    r'rcu_read_unlock\s*\(',
    r'spin_unlock\s*\(',
    r'mutex_unlock\s*\(',
    r'->ops->',
    r'->func\s*\(',
    r'call_rcu\s*\(',
    r'kref_put\s*\(',
]

# Syscalls accesibles sin privilegios — para verificar triggereabilidad
UNPRIVILEGED_SYSCALLS = {
    'socket', 'sendto', 'sendmsg', 'recvfrom', 'recvmsg',
    'bind', 'connect', 'listen', 'accept', 'accept4',
    'setsockopt', 'getsockopt', 'read', 'write', 'ioctl',
    'open', 'openat', 'mmap', 'mprotect', 'mremap',
    'clone', 'fork', 'execve', 'pipe', 'pipe2',
    'msgget', 'msgsnd', 'msgrcv', 'semget', 'semop',
    'shmget', 'shmat', 'inotify_init', 'epoll_create',
    'memfd_create', 'userfaultfd', 'perf_event_open',
    'keyctl', 'add_key', 'request_key',
}

# Capacidades que descalifican para kernelCTF
PRIVILEGED_CAPS = {
    'CAP_NET_ADMIN', 'CAP_SYS_ADMIN', 'CAP_NET_RAW',
    'CAP_SYS_MODULE', 'CAP_SYS_PTRACE', 'CAP_DAC_OVERRIDE',
    'CAP_SETUID', 'CAP_SETGID', 'capable(',
}


# ── Ollama client ──────────────────────────────────────────────────────────────

def ollama_available(model: str) -> bool:
    try:
        import urllib.request
        req = urllib.request.urlopen(f'{OLLAMA_URL}/api/tags', timeout=5)
        data = json.loads(req.read())
        models = [m['name'] for m in data.get('models', [])]
        return any(model in m for m in models)
    except Exception:
        return False


def ollama_generate(prompt: str, model: str, timeout: int = 120) -> str:
    import urllib.request, urllib.error
    payload = json.dumps({
        'model': model,
        'prompt': prompt,
        'stream': False,
        'options': {
            'temperature': 0.1,      # Baja temperatura = menos alucinaciones
            'top_p': 0.9,
            'num_predict': 2048,
            'stop': ['```\n\n', '---\n\n'],
        }
    }).encode()

    try:
        req = urllib.request.Request(
            f'{OLLAMA_URL}/api/generate',
            data=payload,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            result = json.loads(resp.read())
            return result.get('response', '').strip()
    except urllib.error.URLError as e:
        return f'ERROR: Ollama no disponible — {e}'
    except Exception as e:
        return f'ERROR: {e}'


# ── Análisis estático previo (sin LLM) ────────────────────────────────────────

def static_prefilter(code: str, filepath: str) -> dict:
    """
    Filtro estático rápido antes de pasar al LLM.
    Elimina ficheros sin interés para no gastar tokens.
    """
    result = {
        'has_bug_patterns': False,
        'pattern_matches': [],
        'has_privileged_caps': False,
        'privileged_caps_found': [],
        'subsystem_priority': False,
        'loc': len(code.splitlines()),
        'functions': [],
    }

    # Buscar patrones de bugs
    for pattern in BUG_PATTERNS:
        matches = re.findall(pattern, code)
        if matches:
            result['has_bug_patterns'] = True
            result['pattern_matches'].extend(matches[:3])

    # Buscar capabilities privilegiadas
    for cap in PRIVILEGED_CAPS:
        if cap in code:
            result['has_privileged_caps'] = True
            result['privileged_caps_found'].append(cap)

    # Prioridad de subsistema
    for sub in PRIORITY_SUBSYSTEMS:
        if sub in filepath:
            result['subsystem_priority'] = True
            break

    # Extraer nombres de funciones
    funcs = re.findall(r'^(?:static\s+)?(?:\w+\s+)+(\w+)\s*\([^)]*\)\s*\{',
                       code, re.MULTILINE)
    result['functions'] = funcs[:20]

    return result


def extract_suspicious_functions(code: str, max_lines: int = 150) -> list:
    """
    Extrae funciones que contienen patrones sospechosos.
    Evita pasar el fichero completo al LLM.
    """
    suspicious = []
    lines = code.splitlines()

    # Encontrar funciones y sus rangos
    func_starts = []
    for i, line in enumerate(lines):
        if re.match(r'^(?:static\s+)?(?:\w[\w\s\*]+)\s+\w+\s*\([^;]*\)\s*$', line):
            if i + 1 < len(lines) and lines[i+1].strip() == '{':
                func_starts.append(i)
        elif re.match(r'^(?:static\s+)?(?:\w[\w\s\*]+)\s+\w+\s*\([^;]*\)\s*\{', line):
            func_starts.append(i)

    for start in func_starts:
        # Extraer función completa (hasta cierre de llave)
        depth = 0
        end = start
        for i in range(start, min(start + max_lines, len(lines))):
            depth += lines[i].count('{') - lines[i].count('}')
            if depth <= 0 and i > start:
                end = i
                break

        func_code = '\n'.join(lines[start:end+1])

        # Comprobar si tiene patrones sospechosos
        has_pattern = any(re.search(p, func_code) for p in BUG_PATTERNS)
        has_cap     = any(cap in func_code for cap in PRIVILEGED_CAPS)

        if has_pattern and not has_cap:
            suspicious.append({
                'start_line': start + 1,
                'end_line': end + 1,
                'code': func_code[:3000],  # limitar tamaño
            })

    return suspicious[:5]  # máximo 5 funciones por fichero


# ── Prompts para el LLM ────────────────────────────────────────────────────────

SYSTEM_CONTEXT = """You are an expert Linux kernel security researcher focused on finding real, exploitable vulnerabilities.
Your goal is to identify bugs that:
1. Can be triggered WITHOUT root, WITHOUT CAP_NET_ADMIN, WITHOUT CAP_SYS_ADMIN, WITHOUT user namespaces
2. Lead to memory corruption (UAF, OOB write, double free) — NOT just information leaks or panics
3. Are present in Linux kernel LTS 6.12.x
4. Have a realistic exploitation path to LPE (Local Privilege Escalation)

Be extremely strict. Only report bugs you are highly confident about.
DO NOT report: theoretical issues, style problems, missing NULL checks that only cause panics, or anything requiring privileges."""

PASS1_PROMPT = """Analyze this Linux kernel C code for security vulnerabilities.

File: {filepath}
Subsystem: {subsystem}

```c
{code}
```

Look ONLY for:
- Use-After-Free (UAF): object freed then accessed
- Out-of-Bounds write: buffer overflow, array index overflow
- Double free: same pointer freed twice
- Race conditions leading to UAF or OOB
- Type confusion leading to memory corruption

For each finding, answer:
1. Is it triggerable from unprivileged userspace (no CAP_*, no user namespaces)?
2. Which exact syscall sequence triggers it?
3. What is the vulnerable object and its slab cache?
4. Is it a read or write primitive?

Respond in this EXACT JSON format (no markdown, just JSON):
{{
  "findings": [
    {{
      "type": "UAF|OOB_WRITE|DOUBLE_FREE|RACE|TYPE_CONFUSION",
      "function": "function_name",
      "line_approx": 123,
      "description": "one sentence technical description",
      "trigger_syscall": "exact syscall or null if privileged",
      "requires_privileges": true/false,
      "required_caps": ["CAP_X"] or [],
      "object_type": "struct name",
      "slab_cache": "kmalloc-N or cache name or unknown",
      "primitive": "read1|read8|write1|write8|write_controlled|unknown",
      "confidence": 0-100,
      "exploitable_kernelctf": true/false,
      "reasoning": "why this is or isn't exploitable without privileges"
    }}
  ]
}}

If no high-confidence findings, return: {{"findings": []}}"""

PASS2_VERIFICATION_PROMPT = """You previously identified this potential vulnerability. Now verify it rigorously.

File: {filepath}
Finding: {finding_json}

Relevant code context:
```c
{code_context}
```

Answer these verification questions:
1. Is the free/corruption reachable from unprivileged userspace? Trace the exact call path.
2. Is there a lock or RCU protection that prevents the race/UAF?
3. Does the kernel config required for this code path require privileged setup?
4. Is this already fixed in mainline? (check if you see any locking fix pattern)
5. Can an attacker control the freed object's contents after free (heap spray feasibility)?

Respond in EXACT JSON format:
{{
  "verified": true/false,
  "unprivileged_reachable": true/false,
  "call_path": "syscall -> func1 -> func2 -> vulnerable_func",
  "has_sufficient_locking": true/false,
  "locking_analysis": "description of locks present",
  "heap_spray_feasible": true/false,
  "exploitation_difficulty": "easy|medium|hard|very_hard",
  "final_confidence": 0-100,
  "verdict": "REAL_BUG|FALSE_POSITIVE|NEEDS_MORE_ANALYSIS",
  "kernelctf_eligible": true/false,
  "notes": "additional notes"
}}"""


# ── Correlación con crashes de syzkaller ──────────────────────────────────────

def load_syzkaller_crashes(crashes_dir: Path) -> list:
    crashes = []
    if not crashes_dir.exists():
        return crashes

    ignore = [
        "can't ssh", "failed to read from qemu", "no output",
        "lost connection", "executor failed", "suppressed", "SYZFAIL"
    ]

    for crash_dir in crashes_dir.iterdir():
        if not crash_dir.is_dir():
            continue
        desc_file = crash_dir / 'description'
        if not desc_file.exists():
            continue
        desc = desc_file.read_text(errors='replace').strip()
        if any(p.lower() in desc.lower() for p in ignore):
            continue

        report = ''
        for fname in ['report0', 'log0']:
            p = crash_dir / fname
            if p.exists():
                report = p.read_text(errors='replace')[:5000]
                break

        crashes.append({
            'hash': crash_dir.name,
            'description': desc,
            'report': report,
            'has_repro': any((crash_dir / f).exists()
                             for f in ['repro.c', 'repro.cprog', 'repro.prog']),
        })
    return crashes


def correlate_with_crashes(filepath: str, finding: dict, crashes: list) -> dict:
    """
    Busca si algún crash de syzkaller corresponde a este finding.
    """
    func_name = finding.get('function', '')
    obj_type  = finding.get('object_type', '')
    related   = []

    for crash in crashes:
        report = crash['report']
        if func_name and func_name in report:
            related.append(crash['hash'][:12])
        elif obj_type and obj_type in report:
            related.append(crash['hash'][:12])

    return {
        'related_crashes': related,
        'already_triggered': len(related) > 0,
    }


# ── Análisis de diff entre versiones ──────────────────────────────────────────

def analyze_version_diff(kernel_dir: Path, diff_range: str, model: str) -> list:
    """
    Analiza qué cambió entre dos versiones del kernel.
    Busca fixes que revelan bugs todavía presentes en LTS.
    """
    print(f'\n[*] Analizando diff {diff_range}...')

    try:
        result = subprocess.run(
            ['git', 'log', '--oneline', diff_range],
            cwd=kernel_dir, capture_output=True, text=True, timeout=30
        )
        commits = result.stdout.strip().splitlines()
    except Exception as e:
        print(f'    Error: {e}')
        return []

    # Filtrar commits de seguridad
    security_keywords = [
        'use-after-free', 'uaf', 'out-of-bounds', 'oob', 'double free',
        'race condition', 'null ptr', 'null-ptr', 'overflow', 'fix',
        'memory leak', 'refcount', 'locking', 'unlock'
    ]

    interesting = []
    for commit in commits:
        if any(kw in commit.lower() for kw in security_keywords):
            hash_val = commit.split()[0]
            interesting.append(hash_val)

    print(f'    {len(commits)} commits totales, {len(interesting)} interesantes')

    findings = []
    for commit_hash in interesting[:20]:  # limitar a 20
        try:
            diff_result = subprocess.run(
                ['git', 'show', '--stat', '-p', commit_hash],
                cwd=kernel_dir, capture_output=True, text=True, timeout=15
            )
            diff_text = diff_result.stdout[:4000]
        except Exception:
            continue

        # Preguntar al LLM si este fix revela un bug explotable
        prompt = f"""{SYSTEM_CONTEXT}

Analyze this kernel commit diff. Does it fix a bug that could have been exploited from unprivileged userspace?

Commit: {commit_hash}
{diff_text}

Respond in JSON:
{{
  "fixes_exploitable_bug": true/false,
  "bug_type": "UAF|OOB|RACE|OTHER|null",
  "subsystem": "subsystem name",
  "unprivileged_trigger": true/false,
  "affected_versions": "description of what versions are affected",
  "confidence": 0-100,
  "summary": "one sentence"
}}"""

        response = ollama_generate(prompt, model, timeout=60)
        try:
            clean = re.sub(r'```json|```', '', response).strip()
            data  = json.loads(clean)
            if data.get('fixes_exploitable_bug') and data.get('confidence', 0) >= 70:
                data['commit'] = commit_hash
                findings.append(data)
                print(f'    ✓ {commit_hash[:8]} — {data.get("summary", "")}')
        except Exception:
            pass

    return findings


# ── Análisis principal de fichero ──────────────────────────────────────────────

def analyze_file(filepath: Path, model: str, crashes: list,
                 kernel_base: Path = None) -> dict:

    if not filepath.exists():
        return {'error': f'Fichero no encontrado: {filepath}'}

    code = filepath.read_text(errors='replace')
    rel_path = str(filepath.relative_to(kernel_base)) if kernel_base else str(filepath)

    print(f'\n  → {rel_path} ({len(code.splitlines())} líneas)')

    # Filtro estático
    static = static_prefilter(code, rel_path)

    if not static['has_bug_patterns']:
        print(f'    [skip] Sin patrones de bug relevantes')
        return {'filepath': rel_path, 'skipped': True, 'reason': 'no_patterns'}

    # Extraer funciones sospechosas
    suspicious_funcs = extract_suspicious_functions(code)
    if not suspicious_funcs:
        print(f'    [skip] Sin funciones sospechosas sin privilegios')
        return {'filepath': rel_path, 'skipped': True, 'reason': 'no_suspicious_unprivileged'}

    subsystem = '/'.join(rel_path.split('/')[:2])
    all_findings = []

    for func_info in suspicious_funcs:
        func_code = func_info['code']

        # ── PASADA 1: Detección ────────────────────────────────────────────
        prompt1 = PASS1_PROMPT.format(
            filepath=rel_path,
            subsystem=subsystem,
            code=func_code
        )

        print(f'    [P1] Analizando función en línea {func_info["start_line"]}...',
              end='', flush=True)
        response1 = ollama_generate(prompt1, model, timeout=120)

        try:
            clean1 = re.sub(r'```json|```', '', response1).strip()
            # Extraer solo el JSON
            json_match = re.search(r'\{.*\}', clean1, re.DOTALL)
            if not json_match:
                print(' [no JSON]')
                continue
            data1 = json.loads(json_match.group())
        except Exception as e:
            print(f' [parse error: {e}]')
            continue

        findings_p1 = data1.get('findings', [])
        high_conf   = [f for f in findings_p1
                       if f.get('confidence', 0) >= 65
                       and not f.get('requires_privileges', True)]

        if not high_conf:
            print(f' [0 findings con confianza suficiente]')
            continue

        print(f' [{len(high_conf)} candidatos]')

        # ── PASADA 2: Verificación ─────────────────────────────────────────
        for finding in high_conf:
            print(f'    [P2] Verificando: {finding.get("type")} en {finding.get("function")}...',
                  end='', flush=True)

            prompt2 = PASS2_VERIFICATION_PROMPT.format(
                filepath=rel_path,
                finding_json=json.dumps(finding, indent=2),
                code_context=func_code[:2000]
            )

            response2 = ollama_generate(prompt2, model, timeout=120)

            try:
                clean2 = re.sub(r'```json|```', '', response2).strip()
                json_match2 = re.search(r'\{.*\}', clean2, re.DOTALL)
                if not json_match2:
                    print(' [no JSON]')
                    continue
                data2 = json.loads(json_match2.group())
            except Exception as e:
                print(f' [parse error: {e}]')
                continue

            verdict  = data2.get('verdict', 'NEEDS_MORE_ANALYSIS')
            conf_p2  = data2.get('final_confidence', 0)
            eligible = data2.get('kernelctf_eligible', False)

            if verdict == 'REAL_BUG' and conf_p2 >= 70:
                # Correlacionar con crashes de syzkaller
                correlation = correlate_with_crashes(rel_path, finding, crashes)

                final_finding = {
                    'filepath': rel_path,
                    'subsystem': subsystem,
                    'function': finding.get('function'),
                    'line_approx': finding.get('line_approx'),
                    'bug_type': finding.get('type'),
                    'description': finding.get('description'),
                    'trigger_syscall': finding.get('trigger_syscall'),
                    'call_path': data2.get('call_path'),
                    'object_type': finding.get('object_type'),
                    'slab_cache': finding.get('slab_cache'),
                    'primitive': finding.get('primitive'),
                    'exploitation_difficulty': data2.get('exploitation_difficulty'),
                    'heap_spray_feasible': data2.get('heap_spray_feasible'),
                    'locking_analysis': data2.get('locking_analysis'),
                    'confidence_p1': finding.get('confidence'),
                    'confidence_p2': conf_p2,
                    'kernelctf_eligible': eligible,
                    'already_triggered_by_syzkaller': correlation['already_triggered'],
                    'related_crashes': correlation['related_crashes'],
                    'verdict': verdict,
                    'notes': data2.get('notes', ''),
                    'analyzed_at': datetime.now().isoformat(),
                }
                all_findings.append(final_finding)

                sym = '✓✓' if eligible else '✓'
                print(f' [{sym} REAL_BUG conf={conf_p2}%]')
            else:
                print(f' [FALSE_POSITIVE verdict={verdict} conf={conf_p2}%]')

    return {
        'filepath': rel_path,
        'skipped': False,
        'static': static,
        'findings': all_findings,
    }


# ── Análisis de crash existente ────────────────────────────────────────────────

def analyze_crash(crash_dir: Path, model: str, kernel_base: Path) -> dict:
    """
    Dado un directorio de crash de syzkaller, analiza si es explotable
    y busca el código fuente correspondiente.
    """
    desc_file = crash_dir / 'description'
    if not desc_file.exists():
        return {}

    title = desc_file.read_text(errors='replace').strip()
    report = ''
    for fname in ['report0', 'log0']:
        p = crash_dir / fname
        if p.exists():
            report = p.read_text(errors='replace')[:6000]
            break

    if not report:
        return {}

    print(f'\n  → Analizando crash: {title[:70]}')

    prompt = f"""{SYSTEM_CONTEXT}

Analyze this kernel crash report from syzkaller and determine:
1. Is this exploitable for LPE from unprivileged userspace?
2. What is the exact vulnerable object and memory primitive?
3. What exploitation technique would work?
4. Is this suitable for kernelCTF (no CAP_*, no user namespaces)?

Crash title: {title}

Crash report:
```
{report}
```

Respond in JSON:
{{
  "exploitable": true/false,
  "bug_type": "UAF|OOB_WRITE|RACE|DOUBLE_FREE|OTHER",
  "vulnerable_object": "struct name",
  "slab_cache": "cache name",
  "primitive": "read1|write_controlled|etc",
  "unprivileged_trigger": true/false,
  "required_caps": [],
  "trigger_syscall": "syscall name",
  "exploitation_path": "brief description",
  "kernelctf_eligible": true/false,
  "confidence": 0-100,
  "exploitation_difficulty": "easy|medium|hard|very_hard",
  "blocking_factors": ["list of what prevents exploitation"],
  "summary": "one paragraph"
}}"""

    response = ollama_generate(prompt, model, timeout=180)

    try:
        clean = re.sub(r'```json|```', '', response).strip()
        json_match = re.search(r'\{.*\}', clean, re.DOTALL)
        if not json_match:
            return {}
        data = json.loads(json_match.group())
        data['crash_hash'] = crash_dir.name
        data['crash_title'] = title
        data['has_repro'] = any(
            (crash_dir / f).exists()
            for f in ['repro.c', 'repro.cprog', 'repro.prog']
        )

        conf = data.get('confidence', 0)
        eligible = data.get('kernelctf_eligible', False)
        sym = '✓✓' if eligible and conf >= 70 else ('✓' if conf >= 70 else '?')
        print(f'    [{sym}] conf={conf}% eligible={eligible} '
              f'difficulty={data.get("exploitation_difficulty")}')
        return data
    except Exception as e:
        print(f'    [Error: {e}]')
        return {}


# ── Output ─────────────────────────────────────────────────────────────────────

def print_report(results: list, crash_results: list):
    print('\n' + '='*70)
    print('RESUMEN DE ANÁLISIS')
    print('='*70)

    # Bugs en código fuente
    all_findings = []
    for r in results:
        all_findings.extend(r.get('findings', []))

    ctf_eligible   = [f for f in all_findings if f.get('kernelctf_eligible')]
    high_conf      = [f for f in all_findings if f.get('confidence_p2', 0) >= 80]
    already_trigged = [f for f in all_findings if f.get('already_triggered_by_syzkaller')]

    print(f'\n[Análisis de código fuente]')
    print(f'  Ficheros analizados:     {len(results)}')
    print(f'  Findings totales:        {len(all_findings)}')
    print(f'  Alta confianza (≥80%):   {len(high_conf)}')
    print(f'  Elegibles kernelCTF:     {len(ctf_eligible)}')
    print(f'  Ya vistos en syzkaller:  {len(already_trigged)}')

    if ctf_eligible:
        print(f'\n{"─"*70}')
        print('BUGS ELEGIBLES PARA KERNELCTF:')
        for f in sorted(ctf_eligible, key=lambda x: -x.get('confidence_p2', 0)):
            print(f'\n  ✓✓ {f["bug_type"]} en {f["function"]} ({f["filepath"]})')
            print(f'     Confianza: {f["confidence_p2"]}%  '
                  f'Dificultad: {f["exploitation_difficulty"]}')
            print(f'     Objeto:    {f["object_type"]} ({f["slab_cache"]})')
            print(f'     Trigger:   {f["trigger_syscall"]}')
            print(f'     Path:      {f["call_path"]}')
            print(f'     Primitiva: {f["primitive"]}')
            if f['already_triggered_by_syzkaller']:
                print(f'     Syzkaller: ya triggerando — crashes {f["related_crashes"]}')

    # Análisis de crashes
    if crash_results:
        eligible_crashes = [c for c in crash_results
                           if c.get('kernelctf_eligible') and c.get('confidence', 0) >= 70]
        print(f'\n[Análisis de crashes de syzkaller]')
        print(f'  Crashes analizados:      {len(crash_results)}')
        print(f'  Elegibles kernelCTF:     {len(eligible_crashes)}')

        if eligible_crashes:
            print(f'\n  CRASHES ELEGIBLES:')
            for c in sorted(eligible_crashes, key=lambda x: -x.get('confidence', 0)):
                repro = '+ repro' if c.get('has_repro') else 'sin repro'
                print(f'\n    ✓✓ [{repro}] {c["crash_title"][:60]}')
                print(f'       conf={c["confidence"]}% '
                      f'difficulty={c["exploitation_difficulty"]}')
                print(f'       trigger={c["trigger_syscall"]} '
                      f'primitive={c["primitive"]}')
                if c.get('blocking_factors'):
                    print(f'       blockers: {", ".join(c["blocking_factors"][:2])}')


def save_results(results: list, crash_results: list, output_file: Path):
    data = {
        'generated_at': datetime.now().isoformat(),
        'code_analysis': results,
        'crash_analysis': crash_results,
        'summary': {
            'total_files': len(results),
            'total_findings': sum(len(r.get('findings', [])) for r in results),
            'kernelctf_eligible': sum(
                1 for r in results
                for f in r.get('findings', [])
                if f.get('kernelctf_eligible')
            ),
            'crashes_analyzed': len(crash_results),
            'crashes_eligible': sum(
                1 for c in crash_results
                if c.get('kernelctf_eligible') and c.get('confidence', 0) >= 70
            ),
        }
    }
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    print(f'\n[✓] Resultados guardados en: {output_file}')


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Analiza el kernel Linux con Ollama/DeepSeek para encontrar bugs explotables'
    )
    parser.add_argument('--file',     help='Fichero C a analizar')
    parser.add_argument('--dir',      help='Directorio del kernel a analizar recursivamente')
    parser.add_argument('--crashes',  help='Directorio de crashes de syzkaller',
                        default=str(CRASHES_DIR))
    parser.add_argument('--diff',     help='Rango de versiones (ej: v6.12.84..v6.12.85)')
    parser.add_argument('--kernel',   help='Directorio raíz del kernel',
                        default=str(KERNEL_DIR))
    parser.add_argument('--model',    default=DEFAULT_MODEL,
                        help=f'Modelo Ollama (default: {DEFAULT_MODEL})')
    parser.add_argument('--output',   help='Fichero JSON de salida',
                        default=str(OUTPUT_DIR / 'findings.json'))
    parser.add_argument('--only-crashes', action='store_true',
                        help='Analizar solo crashes existentes sin escanear código fuente')
    parser.add_argument('--max-files', type=int, default=50,
                        help='Máximo de ficheros a analizar (default: 50)')
    parser.add_argument('--min-confidence', type=int, default=70,
                        help='Confianza mínima para reportar (default: 70)')
    args = parser.parse_args()

    kernel_base = Path(args.kernel)

    # Verificar Ollama
    print(f'[*] Verificando Ollama con modelo {args.model}...')
    if not ollama_available(args.model):
        print(f'[!] Modelo {args.model} no disponible.')
        print(f'    Instala con: ollama pull {args.model}')
        print(f'    O especifica otro modelo con --model')
        sys.exit(1)
    print(f'[✓] Modelo disponible')

    # Cargar crashes de syzkaller
    crashes_dir = Path(args.crashes)
    crashes     = load_syzkaller_crashes(crashes_dir)
    print(f'[*] Cargados {len(crashes)} crashes de syzkaller')

    results       = []
    crash_results = []

    # ── Analizar crashes existentes ───────────────────────────────────────────
    if crashes:
        print(f'\n[*] Analizando {len(crashes)} crashes con el LLM...')
        for crash in crashes:
            crash_dir = crashes_dir / crash['hash']
            result    = analyze_crash(crash_dir, args.model, kernel_base)
            if result:
                crash_results.append(result)

    if not args.only_crashes:
        # ── Analizar diff de versiones ────────────────────────────────────────
        if args.diff and kernel_base.exists():
            diff_findings = analyze_version_diff(kernel_base, args.diff, args.model)
            print(f'\n[*] Diff analysis: {len(diff_findings)} bugs encontrados')

        # ── Analizar ficheros ─────────────────────────────────────────────────
        files_to_analyze = []

        if args.file:
            files_to_analyze = [Path(args.file)]
        elif args.dir:
            target_dir = Path(args.dir)
            if not target_dir.is_absolute() and kernel_base.exists():
                target_dir = kernel_base / args.dir
            files_to_analyze = sorted(target_dir.rglob('*.c'))[:args.max_files]
            # Priorizar subsistemas de interés
            priority = [f for f in files_to_analyze
                       if any(s in str(f) for s in PRIORITY_SUBSYSTEMS)]
            rest     = [f for f in files_to_analyze if f not in priority]
            files_to_analyze = (priority + rest)[:args.max_files]
        else:
            # Sin --file ni --dir: usar subsistemas de interés del kernel
            if kernel_base.exists():
                for sub in PRIORITY_SUBSYSTEMS:
                    sub_dir = kernel_base / sub
                    if sub_dir.exists():
                        files_to_analyze.extend(sorted(sub_dir.glob('*.c'))[:5])
                files_to_analyze = files_to_analyze[:args.max_files]

        if files_to_analyze:
            print(f'\n[*] Analizando {len(files_to_analyze)} ficheros...')
            for fpath in files_to_analyze:
                result = analyze_file(fpath, args.model, crashes, kernel_base)
                results.append(result)
                # Pausa para no saturar Ollama
                time.sleep(0.5)

    # ── Output ────────────────────────────────────────────────────────────────
    print_report(results, crash_results)
    save_results(results, crash_results, Path(args.output))


if __name__ == '__main__':
    main()
