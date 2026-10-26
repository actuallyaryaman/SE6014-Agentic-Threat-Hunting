"""Independent re-check of every claim, plus a replay of every audited query.

Each claim gets the status of the first problem found:

  unsupported   the claim has nothing to stand on: unknown evidence id, evidence
                from a failed or unaudited call, no cited events, or a cited
                event that can no longer be retrieved
  contradicted  the claim can be checked and is wrong: a quoted fact is not in
                the cited events, a replayed aggregate gives a different bucket,
                the IOC no longer matches, or the text names an IP, number or
                hash that appears nowhere in its evidence
  verified      every check passed
  unverified    the claim could not be checked (offline, the gateway cannot replay
                it, or it cites more events than MAX_EVENTS_PER_CLAIM)

C2 sends claims as "unverified" or, in the current prototype, "self_checked"
(its own structural check passed). C3 re-verifies both and keeps C2's value in
``c2_status``.

Query replay: every successful, replayable call in the audit log runs again.
Its result_hash (result IDs plus total) must match the original.

On top of the hunter design, C3 flags cited events whose text tries to give
instructions to an AI. The text is treated as data and shown to the analyst.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from .audit import REPLAYABLE_TOOLS, response_hash, result_ids
from .contracts import PENDING_STATUSES, AuditRecord, Claim, HuntBundle
from .gateways import Gateway, GatewayUnavailable, NotReplayable
from .injection import scan_for_injection

# A claim may cite up to this many events and all of them are fetched again. A claim that cites more
# is left "unverified". The verifier never checks a sample and then reports the whole claim as verified.
MAX_EVENTS_PER_CLAIM = 500

_IP_RX = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_TS_RX = re.compile(r"\d{4}-\d{2}-\d{2}[T ][\d:.]+Z?|\b\d{1,2}:\d{2}(?::\d{2})?Z?")
_NUM_RX = re.compile(r"(?<![\w.])\d{2,}(?![\w.])")
_HASH_RX = re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")


def _appears(token: str, haystack: str) -> bool:
    """Match a whole token. '50' must not be found inside '2026-10-01T14:00:50', and '10.0.2.10' must not be found inside '10.0.2.100'."""
    return re.search(rf"(?<![\w.:-]){re.escape(token.lower())}(?![\w:-]|\.\d)", haystack) is not None


# Host names look like WS-01, web-01 or HR-LAPTOP-99: letters, dashes and at least one digit.
# Claim, evidence and step ids (C-001, E-T1110-a, T1078-b-203.0.113.99) and dates are not hosts.
_HOST_RX = re.compile(r"(?<![\w.@/\\-])[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)+(?![\w@/\\-])(?!\.\w)")
_ID_LIKE_RX = re.compile(r"^(?:[A-Z]-\d+|[EC]-[\w.-]+|T\d{4}(?:\.\d{3})?-[\w.-]+)$")
# Account patterns. Only high-precision ones are used, because a noisy extractor would reject honest claims:
#   "logged in successfully as admin", "ran as svc_backup"   login context, then "as <name>"
#   user=alice, user: "alice", account svc_backup2           explicit label with a separator, or an account-like token
#   CORP\\alice                                              DOMAIN\\user
_AS_NAME_RX = re.compile(r"\b(?:log(?:ged)?[\s-]*(?:in|on)|login|logon|sign(?:ed)?[\s-]*in|authenticat\w*|ran|executed|running|"
                        r"session|connected|accessed)\b[^.;()]{0,40}?\bas\s+['\"]?([A-Za-z0-9_$][A-Za-z0-9_.$-]*)", re.I)
_LABELLED_RX = re.compile(r"\b(?:user(?:name)?|account)\s*(?:[:=]\s*|\s+)['\"]?([A-Za-z0-9_$][A-Za-z0-9_.$-]*)", re.I)
_DOMAIN_USER_RX = re.compile(r"(?<![\w:\\])([A-Z][A-Z0-9-]+\\[A-Za-z0-9_.$-]+)")
_NOT_A_USER = {"a", "an", "the", "part", "well", "of", "it", "its", "they", "this", "that", "such", "many", "one", "first",
               "new", "non", "in", "on", "at", "to", "for", "from", "with", "per", "any", "all", "each", "other", "more",
               "less", "most", "likely", "expected", "shown", "seen", "noted", "listed", "reported", "described", "follows"}


def _account_like(token: str, labelled_with_separator: bool) -> bool:
    """A labelled token counts as an account when it has a separator, a digit, an underscore or a dollar sign."""
    return labelled_with_separator or any(ch in token for ch in "0123456789_$")


def _entities(text: str) -> tuple[list[str], list[str]]:
    """Return (hosts, accounts) named in a sentence.

    This is a heuristic. It only has to catch names that were made up.
    """
    body = _IP_RX.sub(" ", _TS_RX.sub(" ", text))
    hosts = [h for h in _HOST_RX.findall(body) if any(ch.isdigit() for ch in h) and not _ID_LIKE_RX.match(h)]
    users = [u.rstrip(".") for u in _AS_NAME_RX.findall(body)] + _DOMAIN_USER_RX.findall(body)
    for m in _LABELLED_RX.finditer(body):
        explicit = ":" in m.group(0) or "=" in m.group(0)
        if _account_like(m.group(1), explicit):
            users.append(m.group(1).rstrip("."))
    users = [u for u in users if u and u.lower() not in _NOT_A_USER and not u.isdigit()]
    return list(dict.fromkeys(hosts)), list(dict.fromkeys(users))


def missing_entities(text: str, haystack: str) -> list[str]:
    """Return the IPs, hosts and accounts in ``text`` that appear nowhere in ``haystack``."""
    hosts, users = _entities(text)
    ips = _IP_RX.findall(_TS_RX.sub(" ", text))
    return [e for e in dict.fromkeys(ips + hosts + users) if not _appears(e, haystack)]


def lint_text(text: str, haystack: str) -> list[str]:
    """Return the IPs, hosts, accounts, numbers (2+ digits) and hashes in the text that are missing from the evidence.

    Matching is by whole token. Timestamps and host names are removed before the
    numbers are checked, because their digits are not separate facts.
    """
    missing = missing_entities(text, haystack)
    hosts, _ = _entities(text)
    body = _TS_RX.sub(" ", text)
    for h in hosts:
        body = body.replace(h, " ")
    without_ips = _IP_RX.sub(" ", body)
    missing += [h for h in _HASH_RX.findall(without_ips) if not _appears(h, haystack)]
    without_hashes = _HASH_RX.sub(" ", without_ips)
    missing += [n for n in _NUM_RX.findall(without_hashes) if not _appears(n, haystack)]
    return missing


@dataclass
class VerificationOutcome:
    """What verify_bundle returns: re-verified claims, summary counts, flags and gateway errors."""

    mode: str
    claims: list[Claim]
    summary: dict[str, Any]
    flags: list[dict[str, Any]] = field(default_factory=list)   # hostile event text and similar
    errors: list[str] = field(default_factory=list)


class _Verifier:
    """Holds the state for one verification run: known calls, event cache, flags and errors."""

    def __init__(self, bundle: HuntBundle, gateway: Gateway, max_events: int = MAX_EVENTS_PER_CLAIM) -> None:
        self.bundle = bundle
        self.gateway = gateway
        self.max_events = max_events
        self.calls = bundle.audit_by_id()
        # Calls to C2's analytics server are not in the C1 audit log. Only the run trace records them.
        for a in bundle.analytics_audit:
            self.calls.setdefault(a.call_id, a)
        for t in bundle.trace:
            if t.call_id and t.call_id not in self.calls:
                self.calls[t.call_id] = AuditRecord(call_id=t.call_id, tool=t.tool, params=t.args, total=t.total, ok=t.ok)
        self.evidence = {e.evidence_id: e for e in bundle.evidence}
        self.flags: list[dict[str, Any]] = []
        self.errors: list[str] = []
        self.offline = False
        self._event_cache: dict[str, Any] = {}

    def _step_params(self, step_id: str) -> str:
        """Return the step's own query parameters. A claim may quote them, for example a port filter."""
        step = self.bundle.find_step(step_id) or self.bundle.find_step(step_id.split("@")[0].removesuffix("-ioc"))
        return json.dumps(step.params, default=str).lower() if step else ""

    def _cited_calls_text(self, claim: Claim) -> str:
        parts = []
        for eid in claim.evidence_ids:
            ev = self.evidence.get(eid)
            rec = self.calls.get(ev.call_id) if ev else None
            if rec:
                parts.append(rec.digest.lower())
                parts.append(json.dumps(rec.params, default=str).lower())
        return "\n".join(parts)

    @staticmethod
    def _haystack(docs: list[dict[str, Any]], claim: Claim) -> str:
        values = [str(v) for d in docs for v in d.values()]
        values += [str(v) for v in claim.facts.values()] + [claim.first_seen]
        return "\n".join(values).lower()

    async def _fetch(self, ref: str):
        """Fetch one event by "<index>/<id>" and remember the answer."""
        if ref in self._event_cache:
            return self._event_cache[ref]
        index, _, event_id = ref.partition("/")
        fetched = await self.gateway.get_event(index, event_id)
        self._event_cache[ref] = fetched
        return fetched

    async def verify_claim(self, claim: Claim) -> Claim:
        """Return a copy of the claim with its status and verifier notes filled in."""
        claim = claim.model_copy(deep=True)
        if not claim.c2_status:
            claim.c2_status = claim.status
        if claim.status not in PENDING_STATUSES:       # the hunter already rejected it
            return claim
        claim.status = "unverified"                    # from here on only C3's own states are used
        if self.offline:
            claim.verifier_notes = "not re-verified (offline)"
            return claim

        # Every cited evidence record must exist and come from a successful audited call.
        for eid in claim.evidence_ids or ["<none>"]:
            ev = self.evidence.get(eid)
            rec = self.calls.get(ev.call_id) if ev else None
            if ev is None or rec is None or not rec.ok:
                return self._set(claim, "unsupported", f"evidence {eid} not found in the audit log (or its call failed)")

        consts = self._step_params(claim.step_id) + "\n" + self._cited_calls_text(claim)
        try:
            if claim.kind == "events":
                return await self._verify_events(claim, consts)
            if claim.kind == "aggregate":
                return await self._verify_aggregate(claim, consts)
            return await self._verify_ioc(claim)
        except NotReplayable as exc:
            claim.verifier_notes = f"not re-verified: {exc}"
            return claim
        except GatewayUnavailable as exc:
            self.offline = True
            self.errors.append(str(exc))
            claim.verifier_notes = f"not re-verified: {exc}"
            return claim

    async def _verify_events(self, claim: Claim, consts: str) -> Claim:
        if not claim.event_ids:
            return self._set(claim, "unsupported", "claim cites no events")
        if len(claim.event_ids) > self.max_events:
            return self._set(claim, "unverified", self._too_many_events(claim))
        docs = []
        for ref in claim.event_ids:
            event_result = await self._fetch(ref)
            if event_result.event is None:
                return self._set(claim, "unsupported", f"cited event {ref} is not retrievable: {event_result.error}")
            if scan_for_injection(" ".join(str(v) for v in event_result.event.values() if isinstance(v, str))):
                self.flags.append({"code": "hostile_event_text", "ref": ref, "claim_id": claim.claim_id,
                                   "message": f"cited event {ref} contains text aimed at an AI (claim {claim.claim_id})"})
            docs.append(event_result.event)

        problem = self._check_facts(claim, docs)
        if problem:
            return self._set(claim, "contradicted", problem)
        extra = lint_text(claim.text, self._docs_haystack(docs) + "\n" + consts + "\n" + str(len(claim.event_ids)))
        if extra:
            return self._set(claim, "contradicted", f"claim text contains values not in evidence: {extra}")
        return self._set(claim, "verified", f"re-fetched all {len(claim.event_ids)} cited events; all quoted values match")

    def _too_many_events(self, claim: Claim) -> str:
        """Note for a claim that cites more events than the verifier is allowed to fetch."""
        return (f"not verified: the claim cites {len(claim.event_ids)} events and the limit is {self.max_events}. "
                "C3 does not report a claim as verified when some cited events were never checked")

    @staticmethod
    def _docs_haystack(docs: list[dict[str, Any]]) -> str:
        """Lower-cased values of the retrieved events only. Nothing the claim itself says is included."""
        return "\n".join(str(v) for d in docs for v in d.values()).lower()

    @staticmethod
    def _check_facts(claim: Claim, docs: list[dict[str, Any]], facts: Optional[dict[str, Any]] = None) -> Optional[str]:
        for key, value in (claim.facts if facts is None else facts).items():
            if key == "n_connections":
                if str(len(claim.event_ids)) != str(value):
                    return f"claimed {value} connections, {len(claim.event_ids)} events cited"
            elif isinstance(value, list):
                seen = {str(d.get(key, "")) for d in docs}
                if not {str(v) for v in value} <= seen:
                    return f"{key}: claimed {value}, cited events contain {sorted(seen)}"
            else:
                bad = [d for d in docs if str(d.get(key, "")).lower() != str(value).lower()]
                if bad:
                    return f"{key}={value!r} not present in {len(bad)} of {len(docs)} cited events"
        return None

    def _check_aggregate_facts(self, claim: Claim, bucket: dict[str, Any], docs: list[dict[str, Any]],
                               evidence_text: str) -> Optional[str]:
        """Check the facts of an aggregate claim against the replayed bucket and the retrieved events."""
        facts = dict(claim.facts)
        key = facts.pop("bucket_key", None)
        if key is not None and str(key).lower() != str(bucket.get("key")).lower():
            return f"bucket_key={key!r} differs from the replayed bucket {bucket.get('key')!r}"
        count = facts.pop("count", None)
        if count is not None and str(count) != str(bucket.get("count")):
            return f"count={count!r} differs from the replayed count {bucket.get('count')!r}"
        if docs:
            return self._check_facts(claim, docs, facts)
        for name, value in facts.items():
            values = value if isinstance(value, list) else [value]
            if not all(_appears(str(v), evidence_text) for v in values):
                return f"{name}={value!r} is not backed by the replayed response"
        return None

    def _aggregate_record(self, claim: Claim) -> AuditRecord:
        """Pick the call to replay: the evidence's own audited call, or one built from claim.replay."""
        params = claim.replay.get("params") or {}
        for eid in claim.evidence_ids:
            ev = self.evidence.get(eid)
            rec = self.calls.get(ev.call_id) if ev else None
            if rec and rec.tool == "aggregate" and all(rec.params.get(k) == v for k, v in params.items()):
                return rec
        return AuditRecord(call_id=f"replay-{claim.claim_id}", tool="aggregate", params=params)

    async def _verify_aggregate(self, claim: Claim, consts: str) -> Claim:
        replay_info = claim.replay
        if not replay_info.get("bucket_key") or "count" not in replay_info:
            return self._set(claim, "unsupported", "aggregate claim has no replay information")
        response = await self.gateway.rerun(self._aggregate_record(claim))
        buckets = response.get("result") if isinstance(response.get("result"), list) else []
        bucket = next((x for x in buckets if str(x.get("key")) == str(replay_info["bucket_key"])), None)
        if bucket is None or bucket.get("count") != replay_info["count"]:
            return self._set(claim, "contradicted", "replayed aggregate does not reproduce the bucket")
        if replay_info.get("sum") is not None and abs((bucket.get("sum") or 0) - replay_info["sum"]) > 0.5:
            return self._set(claim, "contradicted", "replayed aggregate sum differs")
        if replay_info.get("distinct") is not None and bucket.get("distinct") != replay_info["distinct"]:
            return self._set(claim, "contradicted", "replayed aggregate distinct count differs")
        notes = ["replayed aggregate reproduces the bucket key, count and sum"]

        docs = []
        field_name = replay_info.get("event_field")
        if field_name and len(claim.event_ids) > self.max_events:
            return self._set(claim, "unverified", self._too_many_events(claim))
        for ref in claim.event_ids if field_name else []:
            event_result = await self._fetch(ref)
            if event_result.event is None or str(event_result.event.get(field_name, "")).lower() != str(replay_info["bucket_key"]).lower():
                return self._set(claim, "contradicted", f"cited event {ref} does not match {field_name}={replay_info['bucket_key']}")
            docs.append(event_result.event)
        if docs:
            notes.append(f"re-fetched all {len(docs)} events behind the bucket; all match")

        # What C2 says in claim.facts must be backed by the replayed response or the retrieved events.
        # It is checked here and is never used as evidence for the claim text.
        evidence_text = self._docs_haystack(docs) + "\n" + consts + "\n" + json.dumps(bucket, default=str).lower()
        problem = self._check_aggregate_facts(claim, bucket, docs, evidence_text)
        if problem:
            return self._set(claim, "contradicted", problem)
        extra = lint_text(claim.text, evidence_text)
        if extra:
            return self._set(claim, "contradicted", f"claim text contains values not in evidence: {extra}")
        return self._set(claim, "verified", "; ".join(notes))

    async def _verify_ioc(self, claim: Claim) -> Claim:
        value = claim.replay.get("value") or claim.facts.get("ioc")
        if not value:
            return self._set(claim, "unsupported", "IOC claim has no value to replay")
        response = await self.gateway.rerun(AuditRecord(call_id=f"replay-{claim.claim_id}", tool="check_ioc", params={"value": value}))
        if not response.get("total"):
            return self._set(claim, "contradicted", "IOC no longer matches on replay")
        return self._set(claim, "verified", "replayed IOC lookup matches")

    @staticmethod
    def _set(claim: Claim, status: str, note: str) -> Claim:
        claim.status = status  # type: ignore[assignment]
        claim.verifier_notes = note
        return claim

    async def replay_queries(self) -> dict[str, Any]:
        """Run every replayable audited call again and compare it with the original."""
        records = [r for r in self.bundle.audit if r.ok and r.tool in REPLAYABLE_TOOLS]
        audited = {r.call_id for r in self.bundle.audit}
        # Calls to C2's analytics server (check_ioc, gap_check, ...) show up in the trace only. Schema 0.2 also
        # writes them to audit/<run_id>-analytics.jsonl. Their hash formula is C2's own, so only totals are compared.
        analytics = {a.call_id: AuditRecord(call_id=a.call_id, tool=a.tool, params=a.params, total=a.total, ok=a.ok)
                     for a in self.bundle.analytics_audit}
        for t in self.bundle.trace:
            if t.server == "analytics" and t.ok and t.call_id not in analytics:
                analytics[t.call_id] = AuditRecord(call_id=t.call_id, tool=t.tool, params=t.args, total=t.total, ok=t.ok)
        records += [a for a in analytics.values() if a.ok and a.tool in REPLAYABLE_TOOLS and a.call_id not in audited]
        identical, mismatches, skipped = 0, [], []
        if self.offline:
            return {"replayed": 0, "identical": 0, "mismatches": [], "skipped": [r.call_id for r in records]}
        for rec in records:
            try:
                response = await self.gateway.rerun(rec)
            except NotReplayable:
                skipped.append(rec.call_id)
                continue
            except GatewayUnavailable as exc:
                self.errors.append(str(exc))
                skipped.extend(x.call_id for x in records[records.index(rec):])
                break
            if "error" in response:
                mismatches.append({"call_id": rec.call_id, "tool": rec.tool, "was": rec.total, "now": None, "error": str(response["error"])[:120]})
                continue
            new_hash = response_hash(rec.tool, response)
            same_hash = (not rec.result_hash) or new_hash == rec.result_hash
            if same_hash and response.get("total") == rec.total:
                identical += 1
            else:
                mismatches.append({"call_id": rec.call_id, "tool": rec.tool, "was": rec.total, "now": response.get("total"),
                                   "ids_now": len(result_ids(rec.tool, response))})
        return {"replayed": identical + len(mismatches), "identical": identical, "mismatches": mismatches, "skipped": skipped}


def check_narrative(bundle: HuntBundle, claims: list[Claim]) -> list[dict[str, Any]]:
    """Check the free text C2 wrote (verdict reasons, rationale, run notes).

    It may only name IPs, hosts and accounts that exist in the run's evidence.
    A hit does not change the verdict. It sends the hunt to an analyst.
    """
    grounded = [claim for claim in claims if claim.status not in ("unsupported", "contradicted")]
    parts = [bundle.plan.hypothesis, json.dumps(bundle.plan.entities, default=str), json.dumps(bundle.plan.time_range)]
    parts += [json.dumps(s.params, default=str) for s in bundle.all_steps()]
    parts += [claim.text + "\n" + json.dumps(claim.facts, default=str) for claim in grounded]
    parts += [json.dumps(e.excerpt, default=str) for e in bundle.evidence]
    parts += [r.digest + "\n" + json.dumps(r.params, default=str) for r in bundle.audit]
    haystack = "\n".join(parts).lower().replace("\\\\", "\\")

    statements: list[tuple[str, str]] = []
    c2_verdict = bundle.c2_verdict
    if c2_verdict is not None:
        statements += [(f"C2 verdict reason {i + 1}", t) for i, t in enumerate(c2_verdict.reasons)]
        extra = (c2_verdict.model_extra or {}).get("rationale")
        if isinstance(extra, str):
            statements.append(("C2 verdict rationale", extra))
    statements += [(f"C2 run note {i + 1}", t) for i, t in enumerate(bundle.hunt_notes)]
    flags = []
    for source, text in statements:
        bad = missing_entities(text, haystack)
        if bad:
            flags.append({"code": "narrative_unsupported_entity", "source": source, "entities": bad, "claim_id": "", "ref": source,
                          "message": f"{source} mentions {', '.join(bad)}, which appear in no evidence"})
    return flags


async def verify_bundle(bundle: HuntBundle, gateway: Gateway, max_events: int = MAX_EVENTS_PER_CLAIM) -> VerificationOutcome:
    """Verify every claim in the bundle, replay the audited queries and collect flags."""
    verifier = _Verifier(bundle, gateway, max_events)
    if gateway.mode == "offline":
        verifier.offline = True
    claims = [await verifier.verify_claim(claim) for claim in bundle.claims]
    replay = await verifier.replay_queries()
    verifier.flags += check_narrative(bundle, claims)
    injection = (bundle.c2_findings or {}).get("prompt_injection") or {}
    if injection.get("total"):
        verifier.flags.append({"code": "c2_prompt_injection", "claim_id": "", "ref": injection.get("call_id", ""), "count": injection["total"],
                               "message": f"C2 found {injection['total']} event(s) with prompt-injection-like text in the hunt window "
                                          f"(call {injection.get('call_id', '?')})"})
    summary = {
        "claims": len(claims),
        "verified": sum(claim.status == "verified" for claim in claims),
        "unsupported": sum(claim.status == "unsupported" for claim in claims),
        "contradicted": sum(claim.status == "contradicted" for claim in claims),
        "unverified": sum(claim.status == "unverified" for claim in claims),
        "narrative_flags": sum(f["code"] == "narrative_unsupported_entity" for f in verifier.flags),
        "replay": replay,
    }
    mode = "offline" if verifier.offline and gateway.mode != "offline" and verifier.errors else gateway.mode
    return VerificationOutcome(mode=mode, claims=claims, summary=summary, flags=verifier.flags, errors=verifier.errors)
