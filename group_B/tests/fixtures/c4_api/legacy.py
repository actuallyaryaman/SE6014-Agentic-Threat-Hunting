#!/usr/bin/env python3
"""Compare two C2 result.json files, ignoring execution-only metadata."""
import argparse
import json
from pathlib import Path

IGNORED = {'run_id', 'call_id', 'query_id', 'timestamp', 'created_at', 'updated_at', 'started_at', 'finished_at', 'execution_timestamp', 'duration_ms', 'seconds'}

def normalize(value):
    if isinstance(value, dict):
        return {k: normalize(v) for k, v in sorted(value.items()) if k not in IGNORED}
    if isinstance(value, list):
        return [normalize(v) for v in value]
    return value

def ids(items, key):
    return sorted({str(item[key]) for item in items if isinstance(item, dict) and item.get(key) is not None})

def compare(a, b):
    metrics = {}
    def field(name, va, vb):
        metrics[name] = {'match': normalize(va) == normalize(vb), 'run_a': normalize(va), 'run_b': normalize(vb)}
    field('hypothesis', a.get('hypothesis'), b.get('hypothesis'))
    field('time_range', a.get('time_range'), b.get('time_range'))
    field('verdict', a.get('verdict'), b.get('verdict'))
    field('coverage', a.get('coverage'), b.get('coverage'))
    field('evidence_ids', ids(a.get('evidence', []), 'evidence_id'), ids(b.get('evidence', []), 'evidence_id'))
    field('cited_event_ids', sorted({x for c in a.get('claims', []) for x in c.get('event_ids', [])}), sorted({x for c in b.get('claims', []) for x in c.get('event_ids', [])}))
    field('queries', a.get('queries', []), b.get('queries', []))
    return metrics

def report(metrics, source_a, source_b):
    lines = ['# C4 C2 Repeatability Comparison', '', f'- Run A: `{source_a}`', f'- Run B: `{source_b}`', '', '| Check | Result |', '|---|---|']
    for key, value in metrics.items():
        lines.append(f"| {key.replace('_', ' ').title()} | {'MATCH' if value['match'] else 'DIFFERENT'} |")
    lines += ['', f"**Matched checks:** {sum(v['match'] for v in metrics.values())}/{len(metrics)}", '', '## Differences', '']
    diffs = [(k, v) for k, v in metrics.items() if not v['match']]
    if not diffs:
        lines.append('No differences in the compared fields. Run IDs and execution metadata are ignored.')
    for key, value in diffs:
        lines.extend([f'### {key}', '', '**Run A**', '```json', json.dumps(value['run_a'], indent=2, ensure_ascii=False), '```', '**Run B**', '```json', json.dumps(value['run_b'], indent=2, ensure_ascii=False), '```'])
    lines += ['', '## Interpretation', '', 'This compares saved C2 results only. Matching outputs indicate agreement in the checked fields, not correctness of the underlying threat-hunting conclusion.', '', '## Recommended repeatability controls', '', 'Use the same dataset snapshot, hypothesis, time window, model settings, code version, and tool configuration. Save both original result files and investigate any changed query, evidence, coverage, or verdict.', '']
    return '\n'.join(lines)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('run_a', type=Path, help='First C2 result.json')
    p.add_argument('run_b', type=Path, help='Second C2 result.json')
    p.add_argument('--output', type=Path, default=Path('c4_comparison.md'))
    args = p.parse_args()
    a = json.loads(args.run_a.read_text(encoding='utf-8'))
    b = json.loads(args.run_b.read_text(encoding='utf-8'))
    metrics = compare(a, b)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report(metrics, args.run_a, args.run_b), encoding='utf-8')
    print(f"Saved {args.output}: {sum(v['match'] for v in metrics.values())}/{len(metrics)} checks matched")

if __name__ == '__main__':
    main()
