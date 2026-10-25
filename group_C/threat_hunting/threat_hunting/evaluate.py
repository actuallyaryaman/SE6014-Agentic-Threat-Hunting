"""Score a run against scenarios/ground_truth.yml (used by tests and experiments, never by the hunt itself).
Ported from the prototype's src/hunt/evaluate.py; reads Elasticsearch directly with the read-only key."""
from __future__ import annotations
import yaml
from elasticsearch import Elasticsearch
from . import config
from .models import ACCEPTED
from .playbooks import DATASETS

EXACT = ("destination.port", "source.ip", "destination.ip", "http.response.status_code")


def es_client() -> Elasticsearch:
    kw = {"api_key": config.ES_API_KEY} if config.ES_API_KEY else {}
    if config.ES_CA_CERT:
        kw["ca_certs"] = config.ES_CA_CERT
    return Elasticsearch(config.ES_URL, request_timeout=30, **kw)


def ground_truth_events(scenario: str = "primary", es=None) -> dict[str, set[str]]:
    es = es or es_client()
    gt = yaml.safe_load((config.SCENARIO_DIR / "ground_truth.yml").read_text())
    out: dict[str, set[str]] = {}
    for item in [i for i in gt["attack_events"] if i["scenario"] == scenario]:
        must = [{"terms": {"event.dataset": DATASETS[item["log_type"]]}}]
        for k, v in item["match"].items():
            if k == "@window":
                a, b = v.split("-")
                must.append({"range": {"@timestamp": {"gte": f"{gt['date']}T{a}:00Z", "lt": f"{gt['date']}T{b}:00Z"}}})
            elif isinstance(v, list):
                must.append({"terms": {k: v}})
            else:
                must.append({"term": {k: v}} if k in EXACT else {"term": {k: {"value": v, "case_insensitive": True}}})
        r = es.search(index=config.HUNT_INDEX, query={"bool": {"filter": must}}, size=500)
        out[item["id"]] = {f'{h["_index"]}/{h["_id"]}' for h in r["hits"]["hits"]}
        assert len(out[item["id"]]) >= item["expected_min"], f"ground truth {item['id']} not found in data"
    return out


def score(result: dict, scenario: str = "primary") -> dict:
    gt = ground_truth_events(scenario)
    cited = {e for c in result["claims"] if c["status"] in ACCEPTED and (not c.get("context_only") or c["technique"] in ("T1059.001", "T1071", "T1190"))
             for e in c.get("event_ids", [])}
    all_gt = set().union(*gt.values())
    per = {k: (len(v & cited) / len(v) if v else 0.0) for k, v in gt.items()}
    return {"gt_items": len(gt), "gt_events": len(all_gt), "cited_events": len(cited),
            "event_recall": round(len(all_gt & cited) / len(all_gt), 3) if all_gt else 0.0,
            "event_precision": round(len(all_gt & cited) / len(cited), 3) if cited else 1.0,
            "per_item_recall": {k: round(v, 2) for k, v in per.items()},
            "items_found": sum(1 for v in per.values() if v > 0)}
