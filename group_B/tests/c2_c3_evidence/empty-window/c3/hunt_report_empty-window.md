# Threat hunt report: empty-window

**Hypothesis:** An external IP brute-forced SSH on DEMO-SSH and then logged in successfully on 2030-01-01.

| | |
|---|---|
| **Verdict** | Inconclusive |
| Confidence | low |
| C2's draft verdict | INSUFFICIENT_DATA (low confidence). C3 review: agrees |
| Analyst review required | yes: confidence is low; coverage gap for T1110, T1078 |
| Time window (UTC) | 2030-01-01T00:00:00Z to 2030-01-02T00:00:00Z |
| Planner | rules |
| Verification | mcp, 0/0 claims verified, replay 8/8 identical |

## 1. Summary

The hunt could not confirm or refute the hypothesis: No telemetry exists for named entities \['DEMO-SSH'\]; absence of events cannot be interpreted.

**Why this verdict**

- No telemetry exists for named entities \['DEMO-SSH'\]; absence of events cannot be interpreted.
- C2 reported INSUFFICIENT\_DATA (low); C3's re-verification agrees.

**What would settle it**

- Check the host name spelling or ingest logs from DEMO-SSH.

## 2. Hunt plan

Techniques tested (required first): `T1110` Brute Force, `T1078` Valid Accounts

Success criteria:

- T1110 (Brute Force): at least 1 independent self-checked indicator(s)
- T1078 (Valid Accounts): at least 1 independent self-checked indicator(s)

Refutation criteria:

- T1110: all required sources and fields covered for the full window AND zero indicators
- T1078: all required sources and fields covered for the full window AND zero indicators

Entities named in the hypothesis: DEMO-SSH. No telemetry for: DEMO-SSH

## 3. Coverage

Data sources in scope: {"auth": 35}

| Technique | Required | Sources | Steps ok / total | Verified claims | Independent steps | Min needed | Covered | Gaps | Not testable with this data |
|---|---|---|---|---|---|---|---|---|---|
| T1110 Brute Force | yes | auth | 1/1 | 0 | 0 | 1 | NO | auth: 24/24 buckets have no events | - |
| T1078 Valid Accounts | yes | auth | 0/0 | 0 | 0 | 1 | NO | no selected data can test it; auth: 24/24 buckets have no events | - |

Events per index in the requested time. An empty bucket is a gap.

| Index | Events | Buckets | Empty buckets |
|---|---|---|---|
| auth | 0 | 24 | 24 |

## 4. Findings (verified claims)

_No verified findings._

## 5. Claims the verifier rejected

_No claim was rejected._

## 6. Benign explanations and baselines considered

- _none recorded_

## 7. Verification summary

- Claims: 0 total, 0 verified, 0 unsupported, 0 contradicted, 0 not re-verified
- Query replay: 8 of 8 identical

## 8. Limitations and data gaps

- Findings depend on the playbooks used; techniques without a playbook are not tested.
- Baselines are synthetic allowlists and must be tuned per environment.
- NOT\_SUPPORTED means no evidence within the covered sources, fields and window, not proof of absence.
- Claims passed C2's structural self-check only; independent re-verification against Elasticsearch is C3's.
- data gap: auth: 24/24 hourly buckets have no events
- A Refuted verdict means there was no evidence in the covered sources and time window. It does not prove the activity did not happen.
- The verifier checks that cited events exist and contain the quoted values. It cannot check that the playbook read them correctly.

## Appendix A. Every query executed (6)

| Call | Tool | Index | Total | OK | Result hash |
|---|---|---|---|---|---|
| `empty-window-0001` | describe_data | - | 35 | yes | `aa6244e314c7bc4f` |
| `empty-window-0002` | count | security-events-c2test* | 0 | yes | `3e6758e523312177` |
| `empty-window-0003` | aggregate | security-events-c2test* | 0 | yes | `2cddd617244d0612` |
| `empty-window-0004` | aggregate | security-events-c2test* | 0 | yes | `bc3a60a2ff2488b0` |
| `empty-window-0005` | aggregate | security-events-c2test* | 0 | yes | `bc3a60a2ff2488b0` |
| `empty-window-0006` | search | security-events-c2test* | 0 | yes | `3e6758e523312177` |

<details><summary>Elasticsearch DSL per query</summary>

`empty-window-0002` count

```json
{
  "query": {
    "bool": {
      "filter": [
        {
          "range": {
            "@timestamp": {
              "gte": "2030-01-01T00:00:00.000Z",
              "lt": "2030-01-02T00:00:00.000Z"
            }
          }
        },
        {
          "term": {
            "host.name": {
              "case_insensitive": true,
              "value": "DEMO-SSH"
            }
          }
        }
      ]
    }
  }
}
```

`empty-window-0003` aggregate

```json
{
  "aggs": {
    "a": {
      "date_histogram": {
        "extended_bounds": {
          "max": "2030-01-01T23:59:59.999Z",
          "min": "2030-01-01T00:00:00.000Z"
        },
        "field": "@timestamp",
        "fixed_interval": "60m",
        "min_doc_count": 0
      }
    }
  },
  "query": {
    "bool": {
      "filter": [
        {
          "range": {
            "@timestamp": {
              "gte": "2030-01-01T00:00:00.000Z",
              "lt": "2030-01-02T00:00:00.000Z"
            }
          }
        },
        {
          "bool": {
            "minimum_should_match": 1,
            "should": [
              {
                "term": {
                  "event.dataset": {
                    "case_insensitive": true,
                    "value": "linux.auth"
                  }
                }
              }
            ]
          }
        }
      ]
    }
  },
  "size": 0
}
```

`empty-window-0004` aggregate

```json
{
  "aggs": {
    "a": {
      "terms": {
        "field": "source.ip",
        "size": 20
      }
    }
  },
  "query": {
    "bool": {
      "filter": [
        {
          "range": {
            "@timestamp": {
              "gte": "2030-01-01T00:00:00.000Z",
              "lt": "2030-01-02T00:00:00.000Z"
            }
          }
        },
        {
          "bool": {
            "minimum_should_match": 1,
            "should": [
              {
                "term": {
                  "event.dataset": {
                    "case_insensitive": true,
                    "value": "linux.auth"
                  }
                }
              }
            ]
          }
        },
        {
          "term": {
            "event.action": {
              "case_insensitive": true,
              "value": "ssh_login"
            }
          }
        },
        {
          "term": {
            "event.outcome": {
              "case_insensitive": true,
              "value": "failure"
            }
          }
        },
        {
          "bool": {
            "minimum_should_match": 1,
            "should": [
              {
                "term": {
                  "host.name": {
                    "case_insensitive": true,
                    "value": "DEMO-SSH"
                  }
                }
              }
            ]
          }
        }
      ]
    }
  },
  "size": 0
}
```

`empty-window-0005` aggregate

```json
{
  "aggs": {
    "a": {
      "terms": {
        "field": "source.ip",
        "size": 20
      }
    }
  },
  "query": {
    "bool": {
      "filter": [
        {
          "range": {
            "@timestamp": {
              "gte": "2030-01-01T00:00:00.000Z",
              "lt": "2030-01-02T00:00:00.000Z"
            }
          }
        },
        {
          "bool": {
            "minimum_should_match": 1,
            "should": [
              {
                "term": {
                  "event.dataset": {
                    "case_insensitive": true,
                    "value": "linux.auth"
                  }
                }
              }
            ]
          }
        },
        {
          "term": {
            "event.action": {
              "case_insensitive": true,
              "value": "ssh_login"
            }
          }
        },
        {
          "term": {
            "event.outcome": {
              "case_insensitive": true,
              "value": "failure"
            }
          }
        },
        {
          "bool": {
            "minimum_should_match": 1,
            "should": [
              {
                "term": {
                  "host.name": {
                    "case_insensitive": true,
                    "value": "DEMO-SSH"
                  }
                }
              }
            ]
          }
        }
      ]
    }
  },
  "size": 0
}
```

`empty-window-0006` search

```json
{
  "query": {
    "bool": {
      "filter": [
        {
          "range": {
            "@timestamp": {
              "gte": "2030-01-01T00:00:00.000Z",
              "lt": "2030-01-02T00:00:00.000Z"
            }
          }
        },
        {
          "bool": {
            "minimum_should_match": 1,
            "should": [
              {
                "wildcard": {
                  "user_agent.original": {
                    "case_insensitive": true,
                    "value": "*ignore all previous instructions*"
                  }
                }
              },
              {
                "wildcard": {
                  "user_agent.original": {
                    "case_insensitive": true,
                    "value": "*ignore previous instructions*"
                  }
                }
              },
              {
                "wildcard": {
                  "user_agent.original": {
                    "case_insensitive": true,
                    "value": "*disregard previous instructions*"
                  }
                }
              },
              {
                "wildcard": {
                  "user_agent.original": {
                    "case_insensitive": true,
                    "value": "*ignore the above*"
                  }
                }
              },
              {
                "wildcard": {
                  "user_agent.original": {
                    "case_insensitive": true,
                    "value": "*system prompt*"
                  }
                }
              },
              {
                "wildcard": {
                  "user.name": {
                    "case_insensitive": true,
                    "value": "*ignore all previous instructions*"
                  }
                }
              },
              {
                "wildcard": {
                  "user.name": {
                    "case_insensitive": true,
                    "value": "*ignore previous instructions*"
                  }
                }
              },
              {
                "wildcard": {
                  "user.name": {
                    "case_insensitive": true,
                    "value": "*disregard previous instructions*"
                  }
                }
              },
              {
                "wildcard": {
                  "user.name": {
                    "case_insensitive": true,
                    "value": "*ignore the above*"
                  }
                }
              },
              {
                "wildcard": {
                  "user.name": {
                    "case_insensitive": true,
                    "value": "*system prompt*"
                  }
                }
              },
              {
                "match_phrase": {
                  "message": "ignore all previous instructions"
                }
              },
              {
                "match_phrase": {
                  "message": "ignore previous instructions"
                }
              },
              {
                "match_phrase": {
                  "message": "disregard previous instructions"
                }
              },
              {
                "match_phrase": {
                  "message": "ignore the above"
                }
              },
              {
                "match_phrase": {
                  "message": "system prompt"
                }
              }
            ]
          }
        }
      ]
    }
  },
  "size": 50,
  "sort": [
    {
      "@timestamp": {
        "order": "asc"
      }
    },
    {
      "event.original": {
        "order": "asc"
      }
    }
  ],
  "track_total_hits": true
}
```

</details>

## Appendix B. Run metadata

| | |
|---|---|
| run_id | empty-window |
| backend | rules (no usable LLM configured) |
| planner | rules |
| code_hash | 8e5620d5f9c668fc |
| tool_calls | 9 |
| seconds | 1.8 |
| python | 3.11.16 |
| temperature | provider default |
| controls | {'canonical_order': True, 'coverage_enforcement': True, 'complete_results': True, 'canonical_params': True} |
| perturb_seed | None |
| index | security-events-c2test* |
| mcp_servers | {'es': 'python -m dev.es_mcp_standin.server', 'analytics': 'python -m analytics_server.server'} |
| ignored_tools | ['es.get_event', 'es.save_finding', 'es.get_audit_log'] |
| audit_files | ['audit/empty-window.jsonl', 'audit/empty-window-analytics.jsonl'] |
| verification_errors | [] |
| report generator | se6014-c3-evidence 1.0.0 |
