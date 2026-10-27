#!/usr/bin/env python3
"""Compare two C3 verification JSON reports and optionally their C2 results."""
import argparse
import json
from pathlib import Path
from compare_c2_results import compare as compare_c2, report as report_c2

# Execution-only keys; audit.ts is the time of the tool call, NOT an event timestamp.
EXEC_IDS = {'run_id', 'report_id', 'call_id', 'query_id'}
META_TIMING = {'seconds', 'phase_seconds', 'audit_files'}

def normalize(value, *, path=()):
    if isinstance(value, dict):
        result = {}
        for key, item in sorted(value.items()):
            if key in EXEC_IDS:
                continue
            if not path and key == 'generated_at':
                continue
            if path and path[-1] == 'meta' and key in META_TIMING:
                continue
            if key == 'ts' and path and 'audit' in path:
                continue
            result[key] = normalize(item, path=path + (key,))
        return result
    if isinstance(value, list):
        return [normalize(item, path=path) for item in value]
    return value

def validate_c3(data, label):
    if not isinstance(data, dict):
        return [f'{label}: root must be a JSON object']
    errors = []
    for field in ('hypothesis', 'plan', 'decision', 'verification', 'coverage', 'audit', 'claim_queries'):
        if field not in data or data[field] is None:
            errors.append(f'{label}: missing {field}')
    if not isinstance(data.get('hypothesis'), str) or not data.get('hypothesis', '').strip():
        errors.append(f'{label}: nonempty hypothesis required')
    plan = data.get('plan')
    if not isinstance(plan, dict) or not isinstance(plan.get('time_range'), dict) or not all(plan['time_range'].get(k) for k in ('from','to')):
        errors.append(f'{label}: plan.time_range.from/to required')
    decision = data.get('decision')
    if not isinstance(decision, dict) or not all(isinstance(decision.get(k), str) and decision[k] for k in ('verdict', 'confidence')):
        errors.append(f'{label}: decision.verdict/confidence required')
    verification = data.get('verification')
    if not isinstance(verification, dict):
        errors.append(f'{label}: verification object required')
    else:
        for key in ('claims', 'verified', 'unsupported', 'contradicted', 'unverified'):
            if not isinstance(verification.get(key), int) or isinstance(verification.get(key), bool) or verification[key] < 0:
                errors.append(f'{label}: verification.{key} nonnegative integer required')
        replay = verification.get('replay')
        if not isinstance(replay, dict) or any(not isinstance(replay.get(k), int) or isinstance(replay.get(k), bool) or replay[k] < 0 for k in ('replayed', 'identical')) or not isinstance(replay.get('mismatches'), list) or not isinstance(replay.get('skipped'), list):
            errors.append(f'{label}: verification.replay incomplete')
    if not isinstance(data.get('coverage'), dict):
        errors.append(f'{label}: coverage object required')
    if not isinstance(data.get('audit'), list):
        errors.append(f'{label}: audit list required')
    if not isinstance(data.get('claim_queries'), dict):
        errors.append(f'{label}: claim_queries object required')
    return errors

def compare_c3(a, b):
    errors = validate_c3(a, 'C3 Run A') + validate_c3(b, 'C3 Run B')
    if errors:
        return {}, errors
    checks = {}
    def check(name, left, right):
        checks[name] = {'match': left == right, 'run_a': left, 'run_b': right}
    for name in ('hypothesis', 'plan', 'decision', 'verification', 'coverage', 'data_sources', 'findings', 'rejected', 'unverified', 'audit', 'claim_queries'):
        if name in a or name in b:
            check(name, normalize(a.get(name), path=(name,)), normalize(b.get(name), path=(name,)))
    for name in sorted((set(a) | set(b)) - {'hypothesis', 'plan', 'decision', 'verification', 'coverage', 'data_sources', 'findings', 'rejected', 'unverified', 'audit', 'claim_queries', 'run_id', 'report_id', 'generated_at'}):
        check(name, normalize(a.get(name), path=(name,)), normalize(b.get(name), path=(name,)))
    return checks, []

def section(title, checks, errors):
    lines = [f'## {title}', '']
    if errors:
        return '\n'.join(lines + ['**INVALID INPUT — not a match**', ''] + [f'- {e}' for e in errors])
    lines += ['| Check | Result |', '|---|---|']
    lines += [f"| {k} | {'MATCH' if v['match'] else 'DIFFERENT'} |" for k,v in checks.items()]
    count = sum(v['match'] for v in checks.values())
    lines += ['', f'**Matched: {count}/{len(checks)} checks**', '']
    for k,v in checks.items():
        if not v['match']:
            lines += [f'### Difference: {k}', '', '**Run A**', '```json', json.dumps(v['run_a'], indent=2, ensure_ascii=False), '```', '**Run B**', '```json', json.dumps(v['run_b'], indent=2, ensure_ascii=False), '```', '']
    return '\n'.join(lines)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('c3_a', type=Path)
    parser.add_argument('c3_b', type=Path)
    parser.add_argument('--c2-a', type=Path)
    parser.add_argument('--c2-b', type=Path)
    parser.add_argument('--output', type=Path, default=Path('c4_c2_c3_comparison.md'))
    args = parser.parse_args()
    if bool(args.c2_a) != bool(args.c2_b):
        parser.error('--c2-a and --c2-b must be provided together')
    a, b = [json.loads(p.read_text(encoding='utf-8')) for p in (args.c3_a, args.c3_b)]
    c3checks, c3errors = compare_c3(a,b)
    lines = ['# C4 Combined C2/C3 Repeatability Comparison', '', f'- C3 A: `{args.c3_a}`', f'- C3 B: `{args.c3_b}`', '', section('C3 verification report comparison', c3checks, c3errors)]
    all_errors = bool(c3errors)
    all_diff = any(not c['match'] for c in c3checks.values())
    if args.c2_a:
        ca,cb = [json.loads(p.read_text(encoding='utf-8')) for p in (args.c2_a,args.c2_b)]
        c2checks,c2errors = compare_c2(ca,cb)
        lines += ['', section('C2 hunt result comparison',c2checks,c2errors)]
        all_errors |= bool(c2errors)
        all_diff |= any(not c['match'] for c in c2checks.values())
        if not c3errors and not c2errors:
            lines += ['', '## Cross-component interpretation', '', f"- C2 A verdict: `{ca['verdict']['label']}`; C2 B verdict: `{cb['verdict']['label']}`", f"- C3 A verdict: `{a['decision']['verdict']}`; C3 B verdict: `{b['decision']['verdict']}`", f"- C3 A replay: `{a['verification']['replay']['identical']}/{a['verification']['replay']['replayed']}` identical; C3 B replay: `{b['verification']['replay']['identical']}/{b['verification']['replay']['replayed']}` identical", '']
    lines += ['', '## Interpretation and limits', '', '- A MATCH indicates equality after excluding documented execution-only identifiers and timestamps; it does not prove that a verdict is correct.', '- `generated_at`, audit call `ts`, run/report/call IDs, and meta execution timings/audit-file paths are excluded.', '- Event timestamps, query DSL/parameters, audit result hashes, evidence contents, verification decisions, and claim links are retained.', '- A DIFFERENT result requires investigation, including whether differences are meaningful or execution-specific.', '']
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text('\n'.join(lines),encoding='utf-8')
    print(f'Saved {args.output}')
    print('INVALID INPUT' if all_errors else 'DIFFERENT' if all_diff else 'MATCH')
    return 2 if all_errors else 1 if all_diff else 0

if __name__ == '__main__':
    raise SystemExit(main())
