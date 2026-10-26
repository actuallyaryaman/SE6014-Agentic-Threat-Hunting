# C4 C2 Repeatability Comparison

- Run A: `attack/result.json`
- Run B: `attack-repeat/result.json`

| Check | Result |
|---|---|
| Hypothesis | MATCH |
| Time Range | MATCH |
| Verdict | DIFFERENT |
| Coverage | MATCH |
| Evidence Ids | MATCH |
| Cited Event Ids | MATCH |
| Queries | DIFFERENT |

**Matched checks:** 5/7

## Differences

### verdict

**Run A**
```json
{
  "confidence": "high",
  "label": "SUPPORTED",
  "leads": [],
  "reasons": [
    "Every required technique has at least the minimum number of independent self-checked indicators."
  ],
  "requires_analyst_review": true,
  "review_reasons": [
    "SUPPORTED verdicts always require analyst review"
  ]
}
```
**Run B**
```json
{
  "confidence": "medium",
  "label": "SUPPORTED",
  "leads": [],
  "reasons": [
    "Every required technique has at least the minimum number of independent self-checked indicators.",
    "A benign explanation the skeptic proposed holds for C-001; confidence is at most medium."
  ],
  "requires_analyst_review": true,
  "review_reasons": [
    "SUPPORTED verdicts always require analyst review",
    "benign explanation not ruled out for C-001: The failures are user demo repeatedly mistyping a password after a credential change, a habit that also produces failures from other source addresses."
  ]
}
```
### queries

**Run A**
```json
[
  {
    "dsl": null,
    "ok": true,
    "phase": "planning",
    "purpose": null,
    "request": {
      "index_pattern": "security-events-c2test*"
    },
    "request_hash": "3da5dd12e6fa5730ba5dce7d56751b9812238d71bc7f12bc2add19da9d5e3ff9",
    "seq": 1,
    "server": "es",
    "step_id": null,
    "tool": "describe_data",
    "total": 35
  },
  {
    "dsl": null,
    "ok": true,
    "phase": "planning",
    "purpose": null,
    "request": {
      "query": "T1110"
    },
    "request_hash": "9e951ff64d0bf170d65c249c6d1fa3220401711a95eb9b36536c60e0bec14ace",
    "seq": 2,
    "server": "analytics",
    "step_id": null,
    "tool": "lookup_attack",
    "total": 1
  },
  {
    "dsl": null,
    "ok": true,
    "phase": "planning",
    "purpose": null,
    "request": {
      "query": "T1078"
    },
    "request_hash": "9ec81361250621332723ea8dcc57774e10bb97589dcac8e9e995c5ccc4fea640",
    "seq": 3,
    "server": "analytics",
    "step_id": null,
    "tool": "lookup_attack",
    "total": 1
  },
  {
    "dsl": {
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
    },
    "ok": true,
    "phase": "planning",
    "purpose": null,
    "request": {
      "filters": [
        {
          "field": "host.name",
          "op": "eq",
          "value": "DEMO-SSH"
        }
      ],
      "index": "security-events-c2test*",
      "time_from": "2026-10-25T00:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "42de196d9ce57ea24fd625fb7fad417ae00d2fcb4e6cb0dd20181479cc392353",
    "seq": 4,
    "server": "es",
    "step_id": null,
    "tool": "count",
    "total": 31
  },
  {
    "dsl": {
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
    },
    "ok": true,
    "phase": "planning",
    "purpose": null,
    "request": {
      "agg": "date_histogram",
      "filters": [
        {
          "field": "event.dataset",
          "op": "in",
          "value": [
            "linux.auth"
          ]
        }
      ],
      "index": "security-events-c2test*",
      "interval": "60m",
      "time_from": "2026-10-25T00:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "a9ee9019a5ef94681b1655e9f379019d04b6c16a0117e9580ac4628d25b20acd",
    "seq": 5,
    "server": "es",
    "step_id": null,
    "tool": "aggregate",
    "total": 35
  },
  {
    "dsl": null,
    "ok": true,
    "phase": "planning",
    "purpose": null,
    "request": {
      "buckets": [
        {
          "count": 35,
          "key": "2026-10-25T00:00:00.000Z"
        }
      ]
    },
    "request_hash": "1a34acfc5b5ea2cf09b09ccb729c4ff87601c15e2cee694aae04ad252085d7a0",
    "seq": 6,
    "server": "analytics",
    "step_id": null,
    "tool": "gap_check",
    "total": 35
  },
  {
    "dsl": {
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
    },
    "ok": true,
    "phase": "planning",
    "purpose": null,
    "request": {
      "filters": [
        {
          "field": "event.dataset",
          "op": "in",
          "value": [
            "linux.auth"
          ]
        },
        {
          "field": "source.ip",
          "op": "exists"
        }
      ],
      "index": "security-events-c2test*",
      "time_from": "2026-10-25T00:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "114da3fa7999757efee8de318807682803313e18f953f403c7bd3215b5b2d360",
    "seq": 7,
    "server": "es",
    "step_id": null,
    "tool": "count",
    "total": 35
  },
  {
    "dsl": {
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
    },
    "ok": true,
    "phase": "planning",
    "purpose": null,
    "request": {
      "filters": [
        {
          "field": "event.dataset",
          "op": "in",
          "value": [
            "linux.auth"
          ]
        },
        {
          "field": "event.action",
          "op": "exists"
        }
      ],
      "index": "security-events-c2test*",
      "time_from": "2026-10-25T00:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "53791da02d80b35037d79b10e35f42a7e9fa8983face87e91c4db3e5335b3518",
    "seq": 8,
    "server": "es",
    "step_id": null,
    "tool": "count",
    "total": 35
  },
  {
    "dsl": {
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
    },
    "ok": true,
    "phase": "planning",
    "purpose": null,
    "request": {
      "filters": [
        {
          "field": "event.dataset",
          "op": "in",
          "value": [
            "linux.auth"
          ]
        },
        {
          "field": "event.outcome",
          "op": "exists"
        }
      ],
      "index": "security-events-c2test*",
      "time_from": "2026-10-25T00:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "0a06864a978b1a122959394377378a13275c9f145b3464e0cce72c94d305bf12",
    "seq": 9,
    "server": "es",
    "step_id": null,
    "tool": "count",
    "total": 35
  },
  {
    "dsl": {
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
    },
    "ok": true,
    "phase": "planning",
    "purpose": null,
    "request": {
      "filters": [
        {
          "field": "event.dataset",
          "op": "in",
          "value": [
            "linux.auth"
          ]
        },
        {
          "field": "user.name",
          "op": "exists"
        }
      ],
      "index": "security-events-c2test*",
      "time_from": "2026-10-25T00:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "91187b295f13270973aa6186881f3897a871226f98d231ad1d13538ba85c759e",
    "seq": 10,
    "server": "es",
    "step_id": null,
    "tool": "count",
    "total": 35
  },
  {
    "dsl": {
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
    },
    "ok": true,
    "phase": "hunt",
    "purpose": "Sources with many failed SSH logins",
    "request": {
      "agg": "terms",
      "field": "source.ip",
      "filters": [
        {
          "field": "event.dataset",
          "op": "in",
          "value": [
            "linux.auth"
          ]
        },
        {
          "field": "event.action",
          "op": "eq",
          "value": "ssh_login"
        },
        {
          "field": "event.outcome",
          "op": "eq",
          "value": "failure"
        },
        {
          "field": "host.name",
          "op": "in",
          "value": [
            "DEMO-SSH"
          ]
        }
      ],
      "index": "security-events-c2test*",
      "size": 20,
      "time_from": "2026-10-25T00:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "27716358e6505ebc4b3903861a02d19df8cd80126573a98339cde7aa6511ad3a",
    "seq": 11,
    "server": "es",
    "step_id": "T1110-a",
    "tool": "aggregate",
    "total": 30
  },
  {
    "dsl": {
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
    },
    "ok": true,
    "phase": "hunt",
    "purpose": "Events behind aggregate bucket 203.0.113.99",
    "request": {
      "fields": [
        "@timestamp",
        "source.ip"
      ],
      "filters": [
        {
          "field": "event.dataset",
          "op": "in",
          "value": [
            "linux.auth"
          ]
        },
        {
          "field": "event.action",
          "op": "eq",
          "value": "ssh_login"
        },
        {
          "field": "event.outcome",
          "op": "eq",
          "value": "failure"
        },
        {
          "field": "host.name",
          "op": "in",
          "value": [
            "DEMO-SSH"
          ]
        },
        {
          "field": "source.ip",
          "op": "eq",
          "value": "203.0.113.99"
        }
      ],
      "index": "security-events-c2test*",
      "size": 100,
      "time_from": "2026-10-25T00:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "94209cbc91bbef72071a24f237c6487532319e83ab6dbec5217359cff9265ed8",
    "seq": 12,
    "server": "es",
    "step_id": "T1110-a-dd-203.0.113.99",
    "tool": "search",
    "total": 30
  },
  {
    "dsl": {
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
    },
    "ok": true,
    "phase": "hunt",
    "purpose": "Brute-force candidates (sources with many failed SSH logins). The Hunter then searches for successful logins after them; no candidate means no login after a brute force can exist, so this step is what tests T1078 when nothing is found",
    "request": {
      "agg": "terms",
      "field": "source.ip",
      "filters": [
        {
          "field": "event.dataset",
          "op": "in",
          "value": [
            "linux.auth"
          ]
        },
        {
          "field": "event.action",
          "op": "eq",
          "value": "ssh_login"
        },
        {
          "field": "event.outcome",
          "op": "eq",
          "value": "failure"
        },
        {
          "field": "host.name",
          "op": "in",
          "value": [
            "DEMO-SSH"
          ]
        }
      ],
      "index": "security-events-c2test*",
      "size": 20,
      "time_from": "2026-10-25T00:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "27716358e6505ebc4b3903861a02d19df8cd80126573a98339cde7aa6511ad3a",
    "seq": 13,
    "server": "es",
    "step_id": "T1078-a",
    "tool": "aggregate",
    "total": 30
  },
  {
    "dsl": {
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
    },
    "ok": true,
    "phase": "hunt",
    "purpose": "First failed SSH login from 203.0.113.99",
    "request": {
      "fields": [
        "@timestamp"
      ],
      "filters": [
        {
          "field": "event.dataset",
          "op": "in",
          "value": [
            "linux.auth"
          ]
        },
        {
          "field": "event.action",
          "op": "eq",
          "value": "ssh_login"
        },
        {
          "field": "source.ip",
          "op": "eq",
          "value": "203.0.113.99"
        },
        {
          "field": "host.name",
          "op": "in",
          "value": [
            "DEMO-SSH"
          ]
        },
        {
          "field": "event.outcome",
          "op": "eq",
          "value": "failure"
        }
      ],
      "index": "security-events-c2test*",
      "size": 1,
      "time_from": "2026-10-25T00:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "51906b2ca5fb21f7d9bab1f7dd27988bc0cdb97a969bc5d8b3c7e1381b414323",
    "seq": 14,
    "server": "es",
    "step_id": "T1078-first-203.0.113.99",
    "tool": "search",
    "total": 30
  },
  {
    "dsl": {
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
    },
    "ok": true,
    "phase": "hunt",
    "purpose": "Successful SSH logins from 203.0.113.99 after its first failed login (2026-10-25T00:10:00.000Z)",
    "request": {
      "fields": [
        "@timestamp",
        "source.ip",
        "user.name",
        "host.name"
      ],
      "filters": [
        {
          "field": "event.dataset",
          "op": "in",
          "value": [
            "linux.auth"
          ]
        },
        {
          "field": "event.action",
          "op": "eq",
          "value": "ssh_login"
        },
        {
          "field": "source.ip",
          "op": "eq",
          "value": "203.0.113.99"
        },
        {
          "field": "host.name",
          "op": "in",
          "value": [
            "DEMO-SSH"
          ]
        },
        {
          "field": "event.outcome",
          "op": "eq",
          "value": "success"
        }
      ],
      "index": "security-events-c2test*",
      "size": 100,
      "time_from": "2026-10-25T00:10:00.000Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "55d06769db48e1ebe140ca9e7250163ef62d211dae8c729054280af8bd5b5843",
    "seq": 15,
    "server": "es",
    "step_id": "T1078-b-203.0.113.99",
    "tool": "search",
    "total": 1
  },
  {
    "dsl": {
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
    },
    "ok": true,
    "phase": "guardrail",
    "purpose": "Prompt-injection sweep over the hunt window",
    "request": {
      "any_of": [
        {
          "field": "user_agent.original",
          "op": "contains",
          "value": "ignore all previous instructions"
        },
        {
          "field": "user_agent.original",
          "op": "contains",
          "value": "ignore previous instructions"
        },
        {
          "field": "user_agent.original",
          "op": "contains",
          "value": "disregard previous instructions"
        },
        {
          "field": "user_agent.original",
          "op": "contains",
          "value": "ignore the above"
        },
        {
          "field": "user_agent.original",
          "op": "contains",
          "value": "system prompt"
        },
        {
          "field": "user.name",
          "op": "contains",
          "value": "ignore all previous instructions"
        },
        {
          "field": "user.name",
          "op": "contains",
          "value": "ignore previous instructions"
        },
        {
          "field": "user.name",
          "op": "contains",
          "value": "disregard previous instructions"
        },
        {
          "field": "user.name",
          "op": "contains",
          "value": "ignore the above"
        },
        {
          "field": "user.name",
          "op": "contains",
          "value": "system prompt"
        },
        {
          "field": "message",
          "op": "contains",
          "value": "ignore all previous instructions"
        },
        {
          "field": "message",
          "op": "contains",
          "value": "ignore previous instructions"
        },
        {
          "field": "message",
          "op": "contains",
          "value": "disregard previous instructions"
        },
        {
          "field": "message",
          "op": "contains",
          "value": "ignore the above"
        },
        {
          "field": "message",
          "op": "contains",
          "value": "system prompt"
        }
      ],
      "fields": [
        "@timestamp",
        "event.dataset",
        "host.name",
        "source.ip",
        "user_agent.original",
        "user.name",
        "message"
      ],
      "index": "security-events-c2test*",
      "size": 50,
      "time_from": "2026-10-25T00:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "0ceb5d78e159f3203e634e2c5953c3c25e3158fb6ae086fbbf0e731fbdc811c2",
    "seq": 16,
    "server": "es",
    "step_id": "guard-injection",
    "tool": "search",
    "total": 0
  },
  {
    "dsl": {
      "aggs": {
        "a": {
          "terms": {
            "field": "user.name",
            "size": 50
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
              "term": {
                "source.ip": "203.0.113.99"
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
      "size": 0
    },
    "ok": true,
    "phase": "skeptic",
    "purpose": "Count distinct usernames in the failed logins from 203.0.113.99; a brute force tries many names, a broken cron/agent retries a single one",
    "request": {
      "agg": "terms",
      "field": "user.name",
      "filters": [
        {
          "field": "source.ip",
          "op": "eq",
          "value": "203.0.113.99"
        },
        {
          "field": "event.outcome",
          "op": "eq",
          "value": "failure"
        }
      ],
      "index": "security-events-c2test*",
      "size": 50,
      "time_from": "2026-10-25T00:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "c2f79d13304e9c0603a795567712e8739f402f408df54cc0edef908e50b55eaf",
    "seq": 17,
    "server": "es",
    "step_id": "SK-01",
    "tool": "aggregate",
    "total": 30
  },
  {
    "dsl": {
      "query": {
        "bool": {
          "filter": [
            {
              "range": {
                "@timestamp": {
                  "gte": "2026-10-18T00:00:00.000Z",
                  "lt": "2026-10-24T23:59:59.000Z"
                }
              }
            },
            {
              "term": {
                "source.ip": "203.0.113.99"
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
      "size": 20,
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
    },
    "ok": true,
    "phase": "skeptic",
    "purpose": "Look for successful logins from the same source on earlier days; recurring successes mean a known managed host rather than a one-off attacker",
    "request": {
      "fields": [
        "@timestamp",
        "source.ip",
        "user.name",
        "host.name",
        "event.outcome"
      ],
      "filters": [
        {
          "field": "source.ip",
          "op": "eq",
          "value": "203.0.113.99"
        },
        {
          "field": "event.outcome",
          "op": "eq",
          "value": "success"
        }
      ],
      "index": "security-events-c2test*",
      "size": 20,
      "time_from": "2026-10-18T00:00:00Z",
      "time_to": "2026-10-24T23:59:59Z"
    },
    "request_hash": "e006720b297502f50507cca0edba47ae8fcfb5ce2b90f8f4e318734bf1eb302d",
    "seq": 18,
    "server": "es",
    "step_id": "SK-02",
    "tool": "search",
    "total": 0
  },
  {
    "dsl": {
      "aggs": {
        "a": {
          "terms": {
            "field": "source.ip",
            "size": 50
          }
        }
      },
      "query": {
        "bool": {
          "filter": [
            {
              "range": {
                "@timestamp": {
                  "gte": "2026-10-18T00:00:00.000Z",
                  "lt": "2026-10-24T23:59:59.000Z"
                }
              }
            },
            {
              "term": {
                "user.name": {
                  "case_insensitive": true,
                  "value": "demo"
                }
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
      "size": 0
    },
    "ok": true,
    "phase": "skeptic",
    "purpose": "Count distinct source IPs authenticating successfully as demo over the preceding week; many sources indicate a shared demo/test account rather than a single compromised credential",
    "request": {
      "agg": "terms",
      "field": "source.ip",
      "filters": [
        {
          "field": "user.name",
          "op": "eq",
          "value": "demo"
        },
        {
          "field": "event.outcome",
          "op": "eq",
          "value": "success"
        }
      ],
      "index": "security-events-c2test*",
      "size": 50,
      "time_from": "2026-10-18T00:00:00Z",
      "time_to": "2026-10-24T23:59:59Z"
    },
    "request_hash": "2483ce0b930996793440f8c733ccf34c3ff16b31d138a77c1ed51be8c810316e",
    "seq": 19,
    "server": "es",
    "step_id": "SK-03",
    "tool": "aggregate",
    "total": 0
  },
  {
    "dsl": {
      "aggs": {
        "a": {
          "date_histogram": {
            "extended_bounds": {
              "max": "2026-10-24T23:59:59.999Z",
              "min": "2026-10-18T00:00:00.000Z"
            },
            "field": "@timestamp",
            "fixed_interval": "1d",
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
                  "gte": "2026-10-18T00:00:00.000Z",
                  "lt": "2026-10-25T00:00:00.000Z"
                }
              }
            },
            {
              "term": {
                "source.ip": "203.0.113.99"
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
      "size": 0
    },
    "ok": true,
    "phase": "skeptic",
    "purpose": "Check whether 203.0.113.99 produced failed SSH logins on multiple days before the hunt, indicating a recurring misconfigured job",
    "request": {
      "agg": "date_histogram",
      "field": "@timestamp",
      "filters": [
        {
          "field": "source.ip",
          "op": "eq",
          "value": "203.0.113.99"
        },
        {
          "field": "event.outcome",
          "op": "eq",
          "value": "failure"
        }
      ],
      "index": "security-events-c2test*",
      "interval": "1d",
      "size": 30,
      "time_from": "2026-10-18T00:00:00Z",
      "time_to": "2026-10-25T00:00:00Z"
    },
    "request_hash": "a30551ba37a26985e7cb21bb36fd88ddc80e6caeda520361a76d6d57ba1d3175",
    "seq": 20,
    "server": "es",
    "step_id": "SK-04",
    "tool": "aggregate",
    "total": 0
  },
  {
    "dsl": {
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
            }
          ]
        }
      },
      "size": 0
    },
    "ok": true,
    "phase": "act",
    "purpose": null,
    "request": {
      "agg": "terms",
      "field": "source.ip",
      "filters": [
        {
          "field": "event.dataset",
          "op": "in",
          "value": [
            "linux.auth"
          ]
        },
        {
          "field": "event.action",
          "op": "eq",
          "value": "ssh_login"
        },
        {
          "field": "event.outcome",
          "op": "eq",
          "value": "failure"
        }
      ],
      "index": "security-events-c2test*",
      "time_from": "2026-10-25T00:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "517ea8c39897b87d70abc0457bdbe6d4df9c8ebd709fc955213d7f375644e51f",
    "seq": 21,
    "server": "es",
    "step_id": null,
    "tool": "aggregate",
    "total": 33
  },
  {
    "dsl": {
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
      "size": 200,
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
    },
    "ok": true,
    "phase": "act",
    "purpose": null,
    "request": {
      "fields": [
        "@timestamp"
      ],
      "filters": [
        {
          "field": "event.dataset",
          "op": "in",
          "value": [
            "linux.auth"
          ]
        },
        {
          "field": "event.action",
          "op": "eq",
          "value": "ssh_login"
        },
        {
          "field": "source.ip",
          "op": "eq",
          "value": "203.0.113.99"
        },
        {
          "field": "event.outcome",
          "op": "eq",
          "value": "success"
        }
      ],
      "index": "security-events-c2test*",
      "size": 200,
      "time_from": "2026-10-25T00:10:00.000Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "8b473ff437c2d12da476a1a90b61926186e02a5f5ed171322361db563f0c598b",
    "seq": 22,
    "server": "es",
    "step_id": null,
    "tool": "search",
    "total": 1
  }
]
```
**Run B**
```json
[
  {
    "dsl": null,
    "ok": true,
    "phase": "planning",
    "purpose": null,
    "request": {
      "index_pattern": "security-events-c2test*"
    },
    "request_hash": "3da5dd12e6fa5730ba5dce7d56751b9812238d71bc7f12bc2add19da9d5e3ff9",
    "seq": 1,
    "server": "es",
    "step_id": null,
    "tool": "describe_data",
    "total": 35
  },
  {
    "dsl": null,
    "ok": true,
    "phase": "planning",
    "purpose": null,
    "request": {
      "query": "T1110"
    },
    "request_hash": "9e951ff64d0bf170d65c249c6d1fa3220401711a95eb9b36536c60e0bec14ace",
    "seq": 2,
    "server": "analytics",
    "step_id": null,
    "tool": "lookup_attack",
    "total": 1
  },
  {
    "dsl": null,
    "ok": true,
    "phase": "planning",
    "purpose": null,
    "request": {
      "query": "T1078"
    },
    "request_hash": "9ec81361250621332723ea8dcc57774e10bb97589dcac8e9e995c5ccc4fea640",
    "seq": 3,
    "server": "analytics",
    "step_id": null,
    "tool": "lookup_attack",
    "total": 1
  },
  {
    "dsl": {
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
    },
    "ok": true,
    "phase": "planning",
    "purpose": null,
    "request": {
      "filters": [
        {
          "field": "host.name",
          "op": "eq",
          "value": "DEMO-SSH"
        }
      ],
      "index": "security-events-c2test*",
      "time_from": "2026-10-25T00:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "42de196d9ce57ea24fd625fb7fad417ae00d2fcb4e6cb0dd20181479cc392353",
    "seq": 4,
    "server": "es",
    "step_id": null,
    "tool": "count",
    "total": 31
  },
  {
    "dsl": {
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
    },
    "ok": true,
    "phase": "planning",
    "purpose": null,
    "request": {
      "agg": "date_histogram",
      "filters": [
        {
          "field": "event.dataset",
          "op": "in",
          "value": [
            "linux.auth"
          ]
        }
      ],
      "index": "security-events-c2test*",
      "interval": "60m",
      "time_from": "2026-10-25T00:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "a9ee9019a5ef94681b1655e9f379019d04b6c16a0117e9580ac4628d25b20acd",
    "seq": 5,
    "server": "es",
    "step_id": null,
    "tool": "aggregate",
    "total": 35
  },
  {
    "dsl": null,
    "ok": true,
    "phase": "planning",
    "purpose": null,
    "request": {
      "buckets": [
        {
          "count": 35,
          "key": "2026-10-25T00:00:00.000Z"
        }
      ]
    },
    "request_hash": "1a34acfc5b5ea2cf09b09ccb729c4ff87601c15e2cee694aae04ad252085d7a0",
    "seq": 6,
    "server": "analytics",
    "step_id": null,
    "tool": "gap_check",
    "total": 35
  },
  {
    "dsl": {
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
    },
    "ok": true,
    "phase": "planning",
    "purpose": null,
    "request": {
      "filters": [
        {
          "field": "event.dataset",
          "op": "in",
          "value": [
            "linux.auth"
          ]
        },
        {
          "field": "source.ip",
          "op": "exists"
        }
      ],
      "index": "security-events-c2test*",
      "time_from": "2026-10-25T00:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "114da3fa7999757efee8de318807682803313e18f953f403c7bd3215b5b2d360",
    "seq": 7,
    "server": "es",
    "step_id": null,
    "tool": "count",
    "total": 35
  },
  {
    "dsl": {
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
    },
    "ok": true,
    "phase": "planning",
    "purpose": null,
    "request": {
      "filters": [
        {
          "field": "event.dataset",
          "op": "in",
          "value": [
            "linux.auth"
          ]
        },
        {
          "field": "event.action",
          "op": "exists"
        }
      ],
      "index": "security-events-c2test*",
      "time_from": "2026-10-25T00:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "53791da02d80b35037d79b10e35f42a7e9fa8983face87e91c4db3e5335b3518",
    "seq": 8,
    "server": "es",
    "step_id": null,
    "tool": "count",
    "total": 35
  },
  {
    "dsl": {
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
    },
    "ok": true,
    "phase": "planning",
    "purpose": null,
    "request": {
      "filters": [
        {
          "field": "event.dataset",
          "op": "in",
          "value": [
            "linux.auth"
          ]
        },
        {
          "field": "event.outcome",
          "op": "exists"
        }
      ],
      "index": "security-events-c2test*",
      "time_from": "2026-10-25T00:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "0a06864a978b1a122959394377378a13275c9f145b3464e0cce72c94d305bf12",
    "seq": 9,
    "server": "es",
    "step_id": null,
    "tool": "count",
    "total": 35
  },
  {
    "dsl": {
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
    },
    "ok": true,
    "phase": "planning",
    "purpose": null,
    "request": {
      "filters": [
        {
          "field": "event.dataset",
          "op": "in",
          "value": [
            "linux.auth"
          ]
        },
        {
          "field": "user.name",
          "op": "exists"
        }
      ],
      "index": "security-events-c2test*",
      "time_from": "2026-10-25T00:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "91187b295f13270973aa6186881f3897a871226f98d231ad1d13538ba85c759e",
    "seq": 10,
    "server": "es",
    "step_id": null,
    "tool": "count",
    "total": 35
  },
  {
    "dsl": {
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
    },
    "ok": true,
    "phase": "hunt",
    "purpose": "Sources with many failed SSH logins",
    "request": {
      "agg": "terms",
      "field": "source.ip",
      "filters": [
        {
          "field": "event.dataset",
          "op": "in",
          "value": [
            "linux.auth"
          ]
        },
        {
          "field": "event.action",
          "op": "eq",
          "value": "ssh_login"
        },
        {
          "field": "event.outcome",
          "op": "eq",
          "value": "failure"
        },
        {
          "field": "host.name",
          "op": "in",
          "value": [
            "DEMO-SSH"
          ]
        }
      ],
      "index": "security-events-c2test*",
      "size": 20,
      "time_from": "2026-10-25T00:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "27716358e6505ebc4b3903861a02d19df8cd80126573a98339cde7aa6511ad3a",
    "seq": 11,
    "server": "es",
    "step_id": "T1110-a",
    "tool": "aggregate",
    "total": 30
  },
  {
    "dsl": {
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
    },
    "ok": true,
    "phase": "hunt",
    "purpose": "Events behind aggregate bucket 203.0.113.99",
    "request": {
      "fields": [
        "@timestamp",
        "source.ip"
      ],
      "filters": [
        {
          "field": "event.dataset",
          "op": "in",
          "value": [
            "linux.auth"
          ]
        },
        {
          "field": "event.action",
          "op": "eq",
          "value": "ssh_login"
        },
        {
          "field": "event.outcome",
          "op": "eq",
          "value": "failure"
        },
        {
          "field": "host.name",
          "op": "in",
          "value": [
            "DEMO-SSH"
          ]
        },
        {
          "field": "source.ip",
          "op": "eq",
          "value": "203.0.113.99"
        }
      ],
      "index": "security-events-c2test*",
      "size": 100,
      "time_from": "2026-10-25T00:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "94209cbc91bbef72071a24f237c6487532319e83ab6dbec5217359cff9265ed8",
    "seq": 12,
    "server": "es",
    "step_id": "T1110-a-dd-203.0.113.99",
    "tool": "search",
    "total": 30
  },
  {
    "dsl": {
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
    },
    "ok": true,
    "phase": "hunt",
    "purpose": "Brute-force candidates (sources with many failed SSH logins). The Hunter then searches for successful logins after them; no candidate means no login after a brute force can exist, so this step is what tests T1078 when nothing is found",
    "request": {
      "agg": "terms",
      "field": "source.ip",
      "filters": [
        {
          "field": "event.dataset",
          "op": "in",
          "value": [
            "linux.auth"
          ]
        },
        {
          "field": "event.action",
          "op": "eq",
          "value": "ssh_login"
        },
        {
          "field": "event.outcome",
          "op": "eq",
          "value": "failure"
        },
        {
          "field": "host.name",
          "op": "in",
          "value": [
            "DEMO-SSH"
          ]
        }
      ],
      "index": "security-events-c2test*",
      "size": 20,
      "time_from": "2026-10-25T00:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "27716358e6505ebc4b3903861a02d19df8cd80126573a98339cde7aa6511ad3a",
    "seq": 13,
    "server": "es",
    "step_id": "T1078-a",
    "tool": "aggregate",
    "total": 30
  },
  {
    "dsl": {
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
    },
    "ok": true,
    "phase": "hunt",
    "purpose": "First failed SSH login from 203.0.113.99",
    "request": {
      "fields": [
        "@timestamp"
      ],
      "filters": [
        {
          "field": "event.dataset",
          "op": "in",
          "value": [
            "linux.auth"
          ]
        },
        {
          "field": "event.action",
          "op": "eq",
          "value": "ssh_login"
        },
        {
          "field": "source.ip",
          "op": "eq",
          "value": "203.0.113.99"
        },
        {
          "field": "host.name",
          "op": "in",
          "value": [
            "DEMO-SSH"
          ]
        },
        {
          "field": "event.outcome",
          "op": "eq",
          "value": "failure"
        }
      ],
      "index": "security-events-c2test*",
      "size": 1,
      "time_from": "2026-10-25T00:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "51906b2ca5fb21f7d9bab1f7dd27988bc0cdb97a969bc5d8b3c7e1381b414323",
    "seq": 14,
    "server": "es",
    "step_id": "T1078-first-203.0.113.99",
    "tool": "search",
    "total": 30
  },
  {
    "dsl": {
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
    },
    "ok": true,
    "phase": "hunt",
    "purpose": "Successful SSH logins from 203.0.113.99 after its first failed login (2026-10-25T00:10:00.000Z)",
    "request": {
      "fields": [
        "@timestamp",
        "source.ip",
        "user.name",
        "host.name"
      ],
      "filters": [
        {
          "field": "event.dataset",
          "op": "in",
          "value": [
            "linux.auth"
          ]
        },
        {
          "field": "event.action",
          "op": "eq",
          "value": "ssh_login"
        },
        {
          "field": "source.ip",
          "op": "eq",
          "value": "203.0.113.99"
        },
        {
          "field": "host.name",
          "op": "in",
          "value": [
            "DEMO-SSH"
          ]
        },
        {
          "field": "event.outcome",
          "op": "eq",
          "value": "success"
        }
      ],
      "index": "security-events-c2test*",
      "size": 100,
      "time_from": "2026-10-25T00:10:00.000Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "55d06769db48e1ebe140ca9e7250163ef62d211dae8c729054280af8bd5b5843",
    "seq": 15,
    "server": "es",
    "step_id": "T1078-b-203.0.113.99",
    "tool": "search",
    "total": 1
  },
  {
    "dsl": {
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
    },
    "ok": true,
    "phase": "guardrail",
    "purpose": "Prompt-injection sweep over the hunt window",
    "request": {
      "any_of": [
        {
          "field": "user_agent.original",
          "op": "contains",
          "value": "ignore all previous instructions"
        },
        {
          "field": "user_agent.original",
          "op": "contains",
          "value": "ignore previous instructions"
        },
        {
          "field": "user_agent.original",
          "op": "contains",
          "value": "disregard previous instructions"
        },
        {
          "field": "user_agent.original",
          "op": "contains",
          "value": "ignore the above"
        },
        {
          "field": "user_agent.original",
          "op": "contains",
          "value": "system prompt"
        },
        {
          "field": "user.name",
          "op": "contains",
          "value": "ignore all previous instructions"
        },
        {
          "field": "user.name",
          "op": "contains",
          "value": "ignore previous instructions"
        },
        {
          "field": "user.name",
          "op": "contains",
          "value": "disregard previous instructions"
        },
        {
          "field": "user.name",
          "op": "contains",
          "value": "ignore the above"
        },
        {
          "field": "user.name",
          "op": "contains",
          "value": "system prompt"
        },
        {
          "field": "message",
          "op": "contains",
          "value": "ignore all previous instructions"
        },
        {
          "field": "message",
          "op": "contains",
          "value": "ignore previous instructions"
        },
        {
          "field": "message",
          "op": "contains",
          "value": "disregard previous instructions"
        },
        {
          "field": "message",
          "op": "contains",
          "value": "ignore the above"
        },
        {
          "field": "message",
          "op": "contains",
          "value": "system prompt"
        }
      ],
      "fields": [
        "@timestamp",
        "event.dataset",
        "host.name",
        "source.ip",
        "user_agent.original",
        "user.name",
        "message"
      ],
      "index": "security-events-c2test*",
      "size": 50,
      "time_from": "2026-10-25T00:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "0ceb5d78e159f3203e634e2c5953c3c25e3158fb6ae086fbbf0e731fbdc811c2",
    "seq": 16,
    "server": "es",
    "step_id": "guard-injection",
    "tool": "search",
    "total": 0
  },
  {
    "dsl": {
      "query": {
        "bool": {
          "filter": [
            {
              "range": {
                "@timestamp": {
                  "gte": "2026-10-18T00:00:00.000Z",
                  "lt": "2026-10-25T00:00:00.000Z"
                }
              }
            },
            {
              "term": {
                "source.ip": "203.0.113.99"
              }
            },
            {
              "term": {
                "user.name": {
                  "case_insensitive": true,
                  "value": "demo"
                }
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
      "size": 10,
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
    },
    "ok": true,
    "phase": "skeptic",
    "purpose": "Check for prior successful demo logins from the same external IP before the hunt window",
    "request": {
      "fields": [
        "@timestamp",
        "host.name",
        "source.ip",
        "user.name",
        "event.action",
        "event.outcome"
      ],
      "filters": [
        {
          "field": "source.ip",
          "op": "eq",
          "value": "203.0.113.99"
        },
        {
          "field": "user.name",
          "op": "eq",
          "value": "demo"
        },
        {
          "field": "event.outcome",
          "op": "eq",
          "value": "success"
        }
      ],
      "index": "security-events-c2test*",
      "size": 10,
      "time_from": "2026-10-18T00:00:00Z",
      "time_to": "2026-10-25T00:00:00Z"
    },
    "request_hash": "1702fd16523f1cff43cf51ef5c5d2f939aa919bae99144b118d43a7fd1f18413",
    "seq": 17,
    "server": "es",
    "step_id": "SK-01",
    "tool": "search",
    "total": 0
  },
  {
    "dsl": {
      "aggs": {
        "a": {
          "terms": {
            "field": "host.name",
            "size": 50
          }
        }
      },
      "query": {
        "bool": {
          "filter": [
            {
              "range": {
                "@timestamp": {
                  "gte": "2026-09-24T01:00:00.000Z",
                  "lt": "2026-10-25T01:00:00.000Z"
                }
              }
            },
            {
              "term": {
                "source.ip": "203.0.113.99"
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
      "size": 0
    },
    "ok": true,
    "phase": "skeptic",
    "purpose": "Check whether the source's failed SSH logins are spread across multiple destination hosts (scanner sweep) rather than concentrated on DEMO-SSH",
    "request": {
      "agg": "terms",
      "field": "host.name",
      "filters": [
        {
          "field": "source.ip",
          "op": "eq",
          "value": "203.0.113.99"
        },
        {
          "field": "event.outcome",
          "op": "eq",
          "value": "failure"
        }
      ],
      "index": "security-events-c2test*",
      "size": 50,
      "time_from": "2026-09-24T01:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "763673861462305d6123355e1a94ec2f7deae7e8045ff4ea6e65aeb04ecb8e23",
    "seq": 18,
    "server": "es",
    "step_id": "SK-02",
    "tool": "aggregate",
    "total": 30
  },
  {
    "dsl": {
      "query": {
        "bool": {
          "filter": [
            {
              "range": {
                "@timestamp": {
                  "gte": "2026-09-24T01:00:00.000Z",
                  "lt": "2026-10-25T01:00:00.000Z"
                }
              }
            },
            {
              "term": {
                "user.name": {
                  "case_insensitive": true,
                  "value": "demo"
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
            }
          ],
          "must_not": [
            {
              "term": {
                "source.ip": "203.0.113.99"
              }
            }
          ]
        }
      }
    },
    "ok": true,
    "phase": "skeptic",
    "purpose": "Look for failed logins of user demo from other source IPs, i.e. the same user failing elsewhere, which fits user error rather than one external brute-forcer",
    "request": {
      "filters": [
        {
          "field": "user.name",
          "op": "eq",
          "value": "demo"
        },
        {
          "field": "event.outcome",
          "op": "eq",
          "value": "failure"
        }
      ],
      "index": "security-events-c2test*",
      "must_not": [
        {
          "field": "source.ip",
          "op": "eq",
          "value": "203.0.113.99"
        }
      ],
      "time_from": "2026-09-24T01:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "39ae18aaa69a6f16c4d29f1c2a2331840408f7e716c135957798de2746fe1446",
    "seq": 19,
    "server": "es",
    "step_id": "SK-03",
    "tool": "count",
    "total": 3
  },
  {
    "dsl": {
      "aggs": {
        "a": {
          "terms": {
            "field": "user.name",
            "size": 50
          }
        }
      },
      "query": {
        "bool": {
          "filter": [
            {
              "range": {
                "@timestamp": {
                  "gte": "2026-09-24T01:00:00.000Z",
                  "lt": "2026-10-25T01:00:00.000Z"
                }
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
      "size": 0
    },
    "ok": true,
    "phase": "skeptic",
    "purpose": "Check whether the same source address serves multiple distinct user names, which indicates a shared NAT/VPN egress rather than a single brute-forcer",
    "request": {
      "agg": "terms",
      "field": "user.name",
      "filters": [
        {
          "field": "source.ip",
          "op": "eq",
          "value": "203.0.113.99"
        }
      ],
      "index": "security-events-c2test*",
      "size": 50,
      "time_from": "2026-09-24T01:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "877616cbee41994ae35d82d98b91aaee387f2f07116601aeb5d1638de2e4d6f3",
    "seq": 20,
    "server": "es",
    "step_id": "SK-04",
    "tool": "aggregate",
    "total": 31
  },
  {
    "dsl": {
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
            }
          ]
        }
      },
      "size": 0
    },
    "ok": true,
    "phase": "act",
    "purpose": null,
    "request": {
      "agg": "terms",
      "field": "source.ip",
      "filters": [
        {
          "field": "event.dataset",
          "op": "in",
          "value": [
            "linux.auth"
          ]
        },
        {
          "field": "event.action",
          "op": "eq",
          "value": "ssh_login"
        },
        {
          "field": "event.outcome",
          "op": "eq",
          "value": "failure"
        }
      ],
      "index": "security-events-c2test*",
      "time_from": "2026-10-25T00:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "517ea8c39897b87d70abc0457bdbe6d4df9c8ebd709fc955213d7f375644e51f",
    "seq": 21,
    "server": "es",
    "step_id": null,
    "tool": "aggregate",
    "total": 33
  },
  {
    "dsl": {
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
      "size": 200,
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
    },
    "ok": true,
    "phase": "act",
    "purpose": null,
    "request": {
      "fields": [
        "@timestamp"
      ],
      "filters": [
        {
          "field": "event.dataset",
          "op": "in",
          "value": [
            "linux.auth"
          ]
        },
        {
          "field": "event.action",
          "op": "eq",
          "value": "ssh_login"
        },
        {
          "field": "source.ip",
          "op": "eq",
          "value": "203.0.113.99"
        },
        {
          "field": "event.outcome",
          "op": "eq",
          "value": "success"
        }
      ],
      "index": "security-events-c2test*",
      "size": 200,
      "time_from": "2026-10-25T00:10:00.000Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "8b473ff437c2d12da476a1a90b61926186e02a5f5ed171322361db563f0c598b",
    "seq": 22,
    "server": "es",
    "step_id": null,
    "tool": "search",
    "total": 1
  }
]
```

## Interpretation

This compares saved C2 results only. Matching outputs indicate agreement in the checked fields, not correctness of the underlying threat-hunting conclusion.

## Recommended repeatability controls

Use the same dataset snapshot, hypothesis, time window, model settings, code version, and tool configuration. Save both original result files and investigate any changed query, evidence, coverage, or verdict.
