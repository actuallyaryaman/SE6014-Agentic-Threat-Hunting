"""B1 full-file test: recognise a log file, load every line into Elasticsearch
through the matching ingest pipeline, and report how many lines parsed.

Usage:  python load_file.py yourfile.log testname
Example: python load_file.py access.log apache-clean
Needs recognise.py in the same folder, and Elasticsearch running on localhost:9200.
Data goes into the index  b1-<testname>  (delete it later with DELETE b1-<testname> in Dev Tools).
"""
import json
import sys
import urllib.error
import urllib.request

from recognise import recognise

ES = "http://localhost:9200"
CHUNK = 500


def bulk(index, pipeline, lines):
    """Send one chunk of raw lines. Return (ok_count, [error reasons])."""
    body = "".join('{"index":{}}\n' + json.dumps({"message": l}) + "\n" for l in lines)
    req = urllib.request.Request(
        f"{ES}/{index}/_bulk?pipeline={pipeline}",
        data=body.encode("utf-8"),
        headers={"Content-Type": "application/x-ndjson"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        result = json.load(resp)
    ok, errors = 0, []
    for item in result["items"]:
        info = item.get("index", {})
        if info.get("error"):
            err = info["error"]
            errors.append(err.get("reason", str(err))[:200])
        else:
            ok += 1
    return ok, errors


def main():
    if len(sys.argv) != 3:
        sys.exit("Usage: python load_file.py <logfile> <testname>")
    path, testname = sys.argv[1], sys.argv[2].lower()
    with open(path, encoding="utf-8-sig", errors="replace") as f:
        lines = [l.rstrip("\r\n") for l in f if l.strip()]

    result = recognise(lines[:50])
    if "reason_code" in result:
        sys.exit(f"Not recognised ({result['reason_code']}). No pipeline to use.")
    name, conf = result["format_id"], result["confidence"]
    pipeline = result["pipeline_id"]
    index = f"b1-{testname}"
    print(f"Format: {name} / {result['dataset']} ({conf:.0%}) -> pipeline '{pipeline}' -> index '{index}'")

    ok, errors = 0, []
    try:
        for i in range(0, len(lines), CHUNK):
            o, e = bulk(index, pipeline, lines[i:i + CHUNK])
            ok += o
            errors += e
    except urllib.error.URLError as exc:
        sys.exit(f"Could not reach Elasticsearch at {ES}: {exc}")

    total = len(lines)
    print(f"Lines in file: {total}")
    print(f"Parsed OK:     {ok} ({ok / total:.1%})")
    print(f"Failed:        {len(errors)}")
    for reason in sorted(set(errors))[:5]:
        print(f"  failure reason: {reason}")


if __name__ == "__main__":
    main()
