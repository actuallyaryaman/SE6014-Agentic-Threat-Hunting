"""Central configuration (env-driven). No secrets are hard-coded.

Loads group_C/threat_hunting/.env and then .env.test (written by dev/setup_test_es.py); real environment variables win."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load_env():
    for name in (".env", ".env.test"):
        f = ROOT / name
        if f.exists():
            for line in f.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip())


_load_env()

# Elasticsearch (used only by the ES MCP server, never by the agent itself)
ES_URL = os.environ.get("ES_URL", "https://localhost:9200")
ES_API_KEY = os.environ.get("ES_API_KEY", "")
ES_CA_CERT = os.environ.get("ES_CA_CERT", "")

# What the agent hunts over (Group B CONTRACTS.md section 6: one integrated index, datasets told apart by event.dataset)
HUNT_INDEX = os.environ.get("HUNT_INDEX", "security-events-*")
HUNT_INDEX_PREFIX = os.environ.get("HUNT_INDEX_PREFIX", "security-events-")

# MCP servers the agent talks to (swap in C1's server here when it exists)
ES_MCP_CMD = os.environ.get("HUNT_ES_MCP_CMD", "python -m dev.es_mcp_standin.server")
ANALYTICS_MCP_CMD = os.environ.get("HUNT_ANALYTICS_MCP_CMD", "python -m analytics_server.server")

KNOWLEDGE_DIR = ROOT / "threat_hunting" / "knowledge"
AUDIT_DIR = ROOT / "audit"
RUNS_DIR = ROOT / "runs"
SCENARIO_DIR = ROOT / "scenarios"

# Guard rails for hunt tools
MAX_RESULT_SIZE = 200
MAX_TERMS_SIZE = 100
MAX_BUCKETS = 1000
MAX_WINDOW_DAYS = 31
QUERY_TIMEOUT_S = 20

# Agent limits (DESIGN.md 3.2): LLM calls per run, investigator turns, and the window used when the hypothesis names no time
LLM_MAX_CALLS = int(os.environ.get("HUNT_LLM_MAX_CALLS", "40"))
AGENT_MAX_STEPS = int(os.environ.get("HUNT_AGENT_MAX_STEPS", "10"))
DEFAULT_LOOKBACK_H = int(os.environ.get("HUNT_DEFAULT_LOOKBACK_H", "24"))
