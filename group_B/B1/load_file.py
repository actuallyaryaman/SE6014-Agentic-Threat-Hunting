"""B1 full-file test: recognise a log file, load every line into Elasticsearch
through the matching ingest pipeline, then CHECK the indexed documents.

Usage:  python load_file.py yourfile.log testname
Example: python load_file.py access.log apache-clean
Needs recognise.py in the same folder, and Elasticsearch running on localhost:9200.
Data goes into the index  b1-<testname>  (delete it later with DELETE b1-<testname> in Dev Tools).
Use a NEW testname each run, so counts are not mixed with an earlier run.

The report shows:
  Indexed        documents Elasticsearch accepted
  Required       documents that have all four required fields, each present AND
                 non-empty (@timestamp, event.dataset, event.original, message)
  Empty values   documents where a required field exists but is empty or only spaces
  Parse failures documents tagged _parse_failure (the pipeline's on_failure handler)
  Parsed OK      indexed, all four required fields non-empty, and NOT tagged _parse_failure
"""
import json
import sys
import urllib.error
import urllib.request

from recognise import recognise

ES = "http://localhost:9200"
CHUNK = 500
REQUIRED = ["@timestamp", "event.dataset", "event.original", "message"]


def es(path, body=None, method="POST"):
    """Call Elasticsearch with a JSON body and return the JSON answer."""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(
        ES + path, data=data, method=method,
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.load(resp)


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


def count(index, query):
    return es(f"/{index}/_count", {"query": query})["count"]


# Text fields that must not be empty. (@timestamp is a date, so it cannot be empty.)
TEXT_REQUIRED = [f for f in REQUIRED if f != "@timestamp"]
# Lucene regexp: one or more characters from tab (9) to space (32) = blank or whitespace only
BLANK = "[" + chr(9) + "-" + chr(32) + "]+"


def empty_clauses(simple=False):
    """Query clauses that match a required text field holding '' or only whitespace.
    Both the field itself and its .keyword copy are checked, because the mapping may be either."""
    clauses = []
    for f in TEXT_REQUIRED:
        for name in (f, f + ".keyword"):
            clauses.append({"term": {name: ""}})
            if not simple:
                clauses.append({"regexp": {name: {"value": BLANK}}})
    return clauses


def check_index(index):
    """Look at the indexed documents. Return (indexed, required, empty, failures, clean)."""
    es(f"/{index}/_refresh")
    exists = {"bool": {"filter": [{"exists": {"field": f}} for f in REQUIRED]}}
    failed_tag = {"bool": {"should": [
        {"term": {"tags": "_parse_failure"}},
        {"term": {"tags.keyword": "_parse_failure"}}], "minimum_should_match": 1}}

    def nonempty(simple):
        return {"bool": {"filter": [exists], "must_not": empty_clauses(simple)}}

    try:
        required = count(index, nonempty(False))
    except urllib.error.HTTPError:  # whitespace regexp rejected: fall back to '' check only
        print("note: whitespace check not supported here, checking for empty strings only")
        simple = True
        required = count(index, nonempty(True))
    else:
        simple = False
    indexed = count(index, {"match_all": {}})
    present = count(index, exists)
    failures = count(index, failed_tag)
    clean = count(index, {"bool": {"filter": [nonempty(simple)], "must_not": [failed_tag]}})
    return indexed, required, present - required, failures, clean


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

    errors = []
    try:
        for i in range(0, len(lines), CHUNK):
            _, e = bulk(index, pipeline, lines[i:i + CHUNK])
            errors += e
        indexed, required, empty, failures, clean = check_index(index)
    except urllib.error.URLError as exc:
        sys.exit(f"Could not reach Elasticsearch at {ES}: {exc}")

    total = len(lines)
    print(f"Lines in file:    {total}")
    print(f"Indexed:          {indexed}")
    print(f"Required fields:  {required} of {indexed} have all four present and non-empty ({', '.join(REQUIRED)})")
    print(f"Empty values:     {empty} documents have a required field that is empty")
    print(f"Parse failures:   {failures} tagged _parse_failure")
    print(f"Parsed OK:        {clean} ({clean / total:.1%})")
    print(f"Rejected by Elasticsearch: {len(errors)}")
    for reason in sorted(set(errors))[:5]:
        print(f"  rejection reason: {reason}")
    if indexed != total:
        print(f"WARNING: indexed ({indexed}) differs from lines in file ({total}). "
              "Was this index used before? Use a new testname.")
    sys.exit(0 if clean == total else 1)


if __name__ == "__main__":
    main()
