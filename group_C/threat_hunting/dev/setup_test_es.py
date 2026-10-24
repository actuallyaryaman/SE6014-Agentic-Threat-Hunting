"""Create the isolated C2 test artifacts in a local Elasticsearch and load the synthetic scenarios through B1's pipelines.

Touches only: ingest pipelines c2test-*, index template c2test-security-events, index security-events-c2test and the API key
c2test-hunt-ro (read + view_index_metadata on security-events-c2test*). Admin credentials come from ES_ADMIN_USER /
ES_ADMIN_PASSWORD and are never printed. ES_URL, the read-only key and HUNT_INDEX are written to .env.test (mode 0600).

python -m dev.setup_test_es [--teardown]"""
from __future__ import annotations
import argparse, hashlib, json, os
from pathlib import Path
from elasticsearch import Elasticsearch, NotFoundError, helpers

ROOT = Path(__file__).resolve().parents[1]
DEV = ROOT / "dev"
ENV_FILE = ROOT / ".env.test"
INDEX, TEMPLATE, KEY_NAME = "security-events-c2test", "c2test-security-events", "c2test-hunt-ro"
PIPELINES = {"auth": "linux-auth", "web": "apache-access", "firewall": "firewall-syslog", "sysmon": "windows-json"}   # log type -> B1 pipeline


def admin() -> tuple[Elasticsearch, str]:
    url = os.environ.get("ES_ADMIN_URL", "http://127.0.0.1:9200")
    kw = {"ca_certs": os.environ["ES_CA_CERT"]} if os.environ.get("ES_CA_CERT") else {}
    es = Elasticsearch(url, basic_auth=(os.environ.get("ES_ADMIN_USER", "elastic"), os.environ["ES_ADMIN_PASSWORD"]), request_timeout=60, **kw)
    return es, url


def pipeline_body(name: str) -> dict:
    body = json.loads((DEV / "b1_pipelines" / f"{name}.json").read_text())
    if name == "windows-json":
        body["processors"] += json.loads((DEV / "b1_pipelines" / "windows_ext.json").read_text())["processors"]
        body["description"] += " + C2 test extension (windows_ext.json)"
    return body


def simulate(es, pid: str, lines: list[str]) -> dict:
    """Parse check: no error, @timestamp and event.dataset set."""
    r = es.ingest.simulate(id=pid, docs=[{"_source": {"message": l}} for l in lines])
    ok = [d for d in r["docs"] if "error" not in d and "@timestamp" in d["doc"]["_source"]
          and d["doc"]["_source"].get("event", {}).get("dataset")]
    return {"parsed": len(ok), "sampled": len(lines), "errors": sorted({d["error"]["reason"][:160] for d in r["docs"] if "error" in d})[:3],
            "missing_timestamp": sum(1 for d in r["docs"] if "error" not in d and "@timestamp" not in d["doc"]["_source"])}


def setup():
    from scenarios import generate
    from scenarios.generate import FILES
    es, url = admin()
    print("generated:", generate.main())
    raw = ROOT / "scenarios" / "raw"
    for name in PIPELINES.values():
        b = pipeline_body(name)
        es.ingest.put_pipeline(id=f"c2test-{name}", description=b.get("description", ""), processors=b["processors"])
    for fname, lt in FILES.items():
        lines = [l for l in (raw / fname).read_text().splitlines() if l.strip()]
        sample = lines[:: max(1, len(lines) // 50)][:50]
        print(f"simulate c2test-{PIPELINES[lt]} on {fname}:", simulate(es, f"c2test-{PIPELINES[lt]}", sample))
    t = json.loads((DEV / "index_template.json").read_text())
    es.indices.put_index_template(name=TEMPLATE, index_patterns=t["index_patterns"], priority=t["priority"], template=t["template"], meta=t["_meta"])
    if es.indices.exists(index=INDEX):
        es.indices.delete(index=INDEX)
    es.indices.create(index=INDEX)
    for fname, lt in FILES.items():
        lines = [l for l in (raw / fname).read_text().splitlines() if l.strip()]
        actions = ({"_index": INDEX, "_id": hashlib.sha256(f"{lt}|{i}|{l}".encode()).hexdigest()[:20], "_source": {"message": l}}
                   for i, l in enumerate(lines))
        ok, errors = helpers.bulk(es, actions, pipeline=f"c2test-{PIPELINES[lt]}", raise_on_error=False, chunk_size=1000)
        reasons = sorted({e["index"]["error"]["reason"][:160] for e in errors})[:3] if errors else []
        print(f"loaded {fname}: {ok}/{len(lines)} indexed" + (f"; {len(errors)} rejected: {reasons}" if errors else ""))
    es.indices.refresh(index=INDEX)
    r = es.search(index=INDEX, size=0, aggs={"ds": {"terms": {"field": "event.dataset"}}, "no_ts": {"missing": {"field": "@timestamp"}}})
    print("docs per event.dataset:", {b["key"]: b["doc_count"] for b in r["aggregations"]["ds"]["buckets"]},
          "| without @timestamp:", r["aggregations"]["no_ts"]["doc_count"])
    try:
        es.security.invalidate_api_key(name=KEY_NAME)
    except NotFoundError:
        pass
    k = es.security.create_api_key(name=KEY_NAME, role_descriptors={"c2test_hunt_ro": {
        "indices": [{"names": [f"{INDEX}*"], "privileges": ["read", "view_index_metadata"]}]}})
    ENV_FILE.touch(mode=0o600)
    ENV_FILE.chmod(0o600)
    ENV_FILE.write_text(f"ES_URL={url}\nES_API_KEY={k['encoded']}\nHUNT_INDEX={INDEX}*\n")
    print(f"read-only API key {KEY_NAME} (id {k['id']}) written to {ENV_FILE.name}")


def teardown():
    es, _ = admin()
    es.indices.delete(index=INDEX, ignore_unavailable=True)
    try:
        es.indices.delete_index_template(name=TEMPLATE)
    except NotFoundError:
        pass
    for name in PIPELINES.values():
        try:
            es.ingest.delete_pipeline(id=f"c2test-{name}")
        except NotFoundError:
            pass
    try:
        es.security.invalidate_api_key(name=KEY_NAME)
    except NotFoundError:
        pass
    ENV_FILE.unlink(missing_ok=True)
    print("removed index, template, pipelines, API key and .env.test")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--teardown", action="store_true")
    teardown() if ap.parse_args().teardown else setup()
