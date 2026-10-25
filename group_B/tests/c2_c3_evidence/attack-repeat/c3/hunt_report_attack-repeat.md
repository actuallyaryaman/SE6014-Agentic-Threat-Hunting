# Threat hunt report: attack-repeat

**Hypothesis:** An external IP brute-forced SSH on DEMO-SSH and then logged in successfully on 2026-10-25.

| | |
|---|---|
| **Verdict** | Inconclusive |
| Confidence | low |
| C2's draft verdict | SUPPORTED (high confidence). C3 review: downgraded |
| Analyst review required | yes: confidence is low; 1 claim(s) failed verification (C-002) |
| Time window (UTC) | 2026-10-25T00:00:00Z to 2026-10-25T01:00:00Z |
| Planner | rules |
| Verification | mcp, 1/2 claims verified, replay 15/15 identical |

## 1. Summary

The hunt could not confirm or refute the hypothesis: T1078 Valid Accounts: no verified indicator.

**Why this verdict**

- T1078 Valid Accounts: no verified indicator.
- C2 reported SUPPORTED (high), but C3 could not confirm it from the log store; the verdict is downgraded to Inconclusive.

## 2. Hunt plan

Techniques tested (required first): `T1110` Brute Force, `T1078` Valid Accounts

Success criteria:

- T1110 (Brute Force): at least 1 independent self-checked indicator(s)
- T1078 (Valid Accounts): at least 1 independent self-checked indicator(s)

Refutation criteria:

- T1110: all required sources and fields covered for the full window AND zero indicators
- T1078: all required sources and fields covered for the full window AND zero indicators

Entities named in the hypothesis: DEMO-SSH

## 3. Coverage

Data sources in scope: {"auth": 35}

| Technique | Required | Sources | Steps ok / total | Verified claims | Independent steps | Min needed | Covered | Gaps | Not testable with this data |
|---|---|---|---|---|---|---|---|---|---|
| T1110 Brute Force | yes | auth | 1/1 | 1 | 1 | 1 | yes | - | - |
| T1078 Valid Accounts | yes | auth | 1/1 | 0 | 0 | 1 | yes | - | - |

Events per index in the requested time. An empty bucket is a gap.

| Index | Events | Buckets | Empty buckets |
|---|---|---|---|
| auth | 35 | 1 | 0 |

## 4. Findings (verified claims)

### T1110 Brute Force

- **C-001** Source 203.0.113.99 produced 30 failed SSH logins
  - first seen: 2026-10-25T00:10:00.000Z, step `T1110-a`, evidence E-T1110-a, E-T1110-a-dd-203.0.113.99
  - query: `attack-repeat-0008` aggregate on `security-events-c2test*`, 2026-10-25T00:00:00Z to 2026-10-25T01:00:00Z (DSL in Appendix A)
  - query: `attack-repeat-0009` search on `security-events-c2test*`, 2026-10-25T00:00:00Z to 2026-10-25T01:00:00Z (DSL in Appendix A)
  - events: `security-events-c2test-2026.10.25/0fc5b18a49f88fc9808f0f8e06d1b3af53da7ddcbd2f3f69e10f1bdad372d303`, `security-events-c2test-2026.10.25/45f4a11017b3168415e00ed7465afd6a5634cac272f96362475b11937f8b32e9`, `security-events-c2test-2026.10.25/9268783196b70b1bb397fbb54d08a189a6a953d66d9d990f2a8afed4b95edb09`, `security-events-c2test-2026.10.25/06be1c9bf55c980f8f5c564e22f24fa401306d86993d79894beaa994bfa6b80b`, `security-events-c2test-2026.10.25/3be1f9b5c88da3f304b4789a3a39649f43e1866196c1a4d754cd73e29aa3bf24`, `security-events-c2test-2026.10.25/13c8429dc7c1415279b12aca62cb3b79da5178a66003397e38f3bb972a381eff`, `security-events-c2test-2026.10.25/5d51071a9a6f77eb9c388bcfb95fa9a8febcb2e052245ed191ab33f70c557964`, `security-events-c2test-2026.10.25/fbef6a83edbe195bc9503b36c0d1e2886baf4fb4fdfc0c38c0bf7ec2acfcf483` (+22 more)
  - verifier: replayed aggregate reproduces the bucket key, count and sum; re-fetched 25 of 30 events behind the bucket; all match

## 5. Claims the verifier rejected

| Claim | Status | Technique | Text | Reason |
|---|---|---|---|---|
| C-002 | contradicted | T1078 | Source 203.0.113.99 logged in successfully as demo on DEMO-SSH after its failed SSH logins began (30 failures from this source in the window) | failed_logins='30' not present in 1 of 1 cited events |

## 6. Benign explanations and baselines considered

- _none recorded_

## 7. Verification summary

- Claims: 2 total, 1 verified, 0 unsupported, 1 contradicted, 0 not re-verified
- Query replay: 15 of 15 identical

## 8. Limitations and data gaps

- Findings depend on the playbooks used; techniques without a playbook are not tested.
- Baselines are synthetic allowlists and must be tuned per environment.
- NOT\_SUPPORTED means no evidence within the covered sources, fields and window, not proof of absence.
- Claims passed C2's structural self-check only; independent re-verification against Elasticsearch is C3's.
- A Refuted verdict means there was no evidence in the covered sources and time window. It does not prove the activity did not happen.
- The verifier checks that cited events exist and contain the quoted values. It cannot check that the playbook read them correctly.

## Appendix A. Every query executed (13)

| Call | Tool | Index | Total | OK | Result hash |
|---|---|---|---|---|---|
| `attack-repeat-0001` | describe_data | - | 35 | yes | `aa6244e314c7bc4f` |
| `attack-repeat-0002` | count | security-events-c2test* | 31 | yes | `b22db16bd5e8ddc3` |
| `attack-repeat-0003` | aggregate | security-events-c2test* | 35 | yes | `9e4a1cbf40f71ba5` |
| `attack-repeat-0004` | count | security-events-c2test* | 35 | yes | `aa6244e314c7bc4f` |
| `attack-repeat-0005` | count | security-events-c2test* | 35 | yes | `aa6244e314c7bc4f` |
| `attack-repeat-0006` | count | security-events-c2test* | 35 | yes | `aa6244e314c7bc4f` |
| `attack-repeat-0007` | count | security-events-c2test* | 35 | yes | `aa6244e314c7bc4f` |
| `attack-repeat-0008` | aggregate | security-events-c2test* | 30 | yes | `29777b1343d94f20` |
| `attack-repeat-0009` | search | security-events-c2test* | 30 | yes | `1adb80242af6d627` |
| `attack-repeat-0010` | aggregate | security-events-c2test* | 30 | yes | `29777b1343d94f20` |
| `attack-repeat-0011` | search | security-events-c2test* | 30 | yes | `6be3efdfc1f46fd9` |
| `attack-repeat-0012` | search | security-events-c2test* | 1 | yes | `bccf55cb0f7a3b52` |
| `attack-repeat-0013` | search | security-events-c2test* | 0 | yes | `3e6758e523312177` |

<details><summary>Elasticsearch DSL per query</summary>

`attack-repeat-0002` count

```json
{
  "query": {
    "bool": {
      "filter": [
        {
          "range": {
            "@timestamp": {
              "gte": "2026-10-25T00:00:00.000Z",
              "lt": "2026-10-25T01:00:00.000Z"
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

`attack-repeat-0003` aggregate

```json
{
  "aggs": {
    "a": {
      "date_histogram": {
        "extended_bounds": {
          "max": "2026-10-25T00:59:59.999Z",
          "min": "2026-10-25T00:00:00.000Z"
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
              "gte": "2026-10-25T00:00:00.000Z",
              "lt": "2026-10-25T01:00:00.000Z"
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

`attack-repeat-0004` count

```json
{
  "query": {
    "bool": {
      "filter": [
        {
          "range": {
            "@timestamp": {
              "gte": "2026-10-25T00:00:00.000Z",
              "lt": "2026-10-25T01:00:00.000Z"
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
          "exists": {
            "field": "source.ip"
          }
        }
      ]
    }
  }
}
```

`attack-repeat-0005` count

```json
{
  "query": {
    "bool": {
      "filter": [
        {
          "range": {
            "@timestamp": {
              "gte": "2026-10-25T00:00:00.000Z",
              "lt": "2026-10-25T01:00:00.000Z"
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
          "exists": {
            "field": "event.action"
          }
        }
      ]
    }
  }
}
```

`attack-repeat-0006` count

```json
{
  "query": {
    "bool": {
      "filter": [
        {
          "range": {
            "@timestamp": {
              "gte": "2026-10-25T00:00:00.000Z",
              "lt": "2026-10-25T01:00:00.000Z"
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
          "exists": {
            "field": "event.outcome"
          }
        }
      ]
    }
  }
}
```

`attack-repeat-0007` count

```json
{
  "query": {
    "bool": {
      "filter": [
        {
          "range": {
            "@timestamp": {
              "gte": "2026-10-25T00:00:00.000Z",
              "lt": "2026-10-25T01:00:00.000Z"
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
          "exists": {
            "field": "user.name"
          }
        }
      ]
    }
  }
}
```

`attack-repeat-0008` aggregate

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
              "gte": "2026-10-25T00:00:00.000Z",
              "lt": "2026-10-25T01:00:00.000Z"
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

`attack-repeat-0009` search

```json
{
  "query": {
    "bool": {
      "filter": [
        {
          "range": {
            "@timestamp": {
              "gte": "2026-10-25T00:00:00.000Z",
              "lt": "2026-10-25T01:00:00.000Z"
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
        },
        {
          "term": {
            "source.ip": "203.0.113.99"
          }
        }
      ]
    }
  },
  "size": 100,
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

`attack-repeat-0010` aggregate

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
              "gte": "2026-10-25T00:00:00.000Z",
              "lt": "2026-10-25T01:00:00.000Z"
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

`attack-repeat-0011` search

```json
{
  "query": {
    "bool": {
      "filter": [
        {
          "range": {
            "@timestamp": {
              "gte": "2026-10-25T00:00:00.000Z",
              "lt": "2026-10-25T01:00:00.000Z"
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
            "source.ip": "203.0.113.99"
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
        },
        {
          "term": {
            "event.outcome": {
              "case_insensitive": true,
              "value": "failure"
            }
          }
        }
      ]
    }
  },
  "size": 1,
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

`attack-repeat-0012` search

```json
{
  "query": {
    "bool": {
      "filter": [
        {
          "range": {
            "@timestamp": {
              "gte": "2026-10-25T00:10:00.000Z",
              "lt": "2026-10-25T01:00:00.000Z"
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
            "source.ip": "203.0.113.99"
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
        },
        {
          "term": {
            "event.outcome": {
              "case_insensitive": true,
              "value": "success"
            }
          }
        }
      ]
    }
  },
  "size": 100,
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

`attack-repeat-0013` search

```json
{
  "query": {
    "bool": {
      "filter": [
        {
          "range": {
            "@timestamp": {
              "gte": "2026-10-25T00:00:00.000Z",
              "lt": "2026-10-25T01:00:00.000Z"
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
| run_id | attack-repeat |
| backend | rules (no usable LLM configured) |
| planner | rules |
| code_hash | 8e5620d5f9c668fc |
| tool_calls | 16 |
| seconds | 0.9 |
| python | 3.11.16 |
| temperature | provider default |
| controls | {'canonical_order': True, 'coverage_enforcement': True, 'complete_results': True, 'canonical_params': True} |
| perturb_seed | None |
| index | security-events-c2test* |
| mcp_servers | {'es': 'python -m dev.es_mcp_standin.server', 'analytics': 'python -m analytics_server.server'} |
| ignored_tools | ['es.get_event', 'es.save_finding', 'es.get_audit_log'] |
| audit_files | ['audit/attack-repeat.jsonl', 'audit/attack-repeat-analytics.jsonl'] |
| verification_errors | [] |
| report generator | se6014-c3-evidence 1.0.0 |
