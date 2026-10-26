# C4 C2 Repeatability Comparison

- Run A: `attack/result.json`
- Run B: `attack-repeat/result.json`

| Check | Result |
|---|---|
| hypothesis | MATCH |
| time_range | MATCH |
| verdict | DIFFERENT |
| coverage | MATCH |
| claims_and_evidence_links | DIFFERENT |
| evidence_contents | DIFFERENT |
| queries_and_values | DIFFERENT |
| actions | DIFFERENT |
| agent | DIFFERENT |
| candidates | MATCH |
| dynamic_steps | DIFFERENT |
| findings | MATCH |
| intake | DIFFERENT |
| lesson_flags | MATCH |
| lessons_used | MATCH |
| limitations | MATCH |
| manifest | DIFFERENT |
| notes | MATCH |
| question | MATCH |
| schema_version | MATCH |
| self_check | DIFFERENT |
| skeptic | DIFFERENT |
| step_results | DIFFERENT |
| techniques | DIFFERENT |

**Matched checks: 11/24**

## Differences

### verdict

**Run A**
```json
{
  "label": "SUPPORTED",
  "confidence": "high",
  "requires_analyst_review": true,
  "review_reasons": [
    "SUPPORTED verdicts always require analyst review",
    "2 lead(s) from LLM-proposed queries (C-003, C-004) need review"
  ],
  "reasons": [
    "Every required technique has at least the minimum number of independent self-checked indicators."
  ],
  "leads": [
    "C-003",
    "C-004"
  ]
}
```
**Run B**
```json
{
  "label": "SUPPORTED",
  "confidence": "high",
  "requires_analyst_review": true,
  "review_reasons": [
    "SUPPORTED verdicts always require analyst review",
    "1 lead(s) from LLM-proposed queries (C-003) need review"
  ],
  "reasons": [
    "Every required technique has at least the minimum number of independent self-checked indicators."
  ],
  "leads": [
    "C-003"
  ]
}
```

### claims_and_evidence_links

**Run A**
```json
[
  {
    "claim_id": "C-001",
    "confidence": "medium",
    "context_only": false,
    "event_ids": [
      "security-events-c2test-2026.10.26/a57e0c8b67ef5d90eb0e704ac64eaf239d969d0030b0c46eca8319696b221f4e",
      "security-events-c2test-2026.10.26/c5d6eb0a97fca952a5de6fe59153386ebf16d7d2ee49891f2b43de9af1030d43",
      "security-events-c2test-2026.10.26/4397d8bc44453ccff0dfc97cad262ea70fd5fef74461aa1c7b2baa3068c0b24a",
      "security-events-c2test-2026.10.26/9427c3870671bf6d79f92eec44b38ac5f36be9738c947a77d6b47d9a5c0657b5",
      "security-events-c2test-2026.10.26/1c26d821e31182b7ed37906d46a3d0c1f6befdeec1f9199e6b757d1f6e362748",
      "security-events-c2test-2026.10.26/7437ece1f2aba338a445b51a8f5051deb5d2e5a608327df266687ec03a066d62",
      "security-events-c2test-2026.10.26/a566b4df52091ab96a9689fd7b75d6a6e6e5272cc733269fb075de55e374b48c",
      "security-events-c2test-2026.10.26/973349b2ca40bc2ecc261acbad2ee5419660116bd8076d3b4de1699a9dbf6cbd",
      "security-events-c2test-2026.10.26/fc8d33d3cd7a78e4a07cc6a3a343216f1bf4f39349c15b9e4c9b29390598e0b1",
      "security-events-c2test-2026.10.26/2208186b4c033e8f8d0585b7c62e67a6aea7d3fe1ae1f93aa8f828af5a0bbb8e",
      "security-events-c2test-2026.10.26/80fdb790b3ba5a403398076a16c72f64a5c7bff83e623fe2e65e8d84925b82ce",
      "security-events-c2test-2026.10.26/37e55e177a81f58e395b43f0e3bd0ba0e5d76cf673f9e8489bb703c07e78e937",
      "security-events-c2test-2026.10.26/dbab3ff1dadea5083f3b55cc2594bc5ecaade288d0855f09b97b0d5e53ffb999",
      "security-events-c2test-2026.10.26/d82f90db6b09b5f80ce70f89015f67f1d25a21ae627d7e57920e7b709f0c5a93",
      "security-events-c2test-2026.10.26/012a4728b1f6819f4acc48210e6528c0e61fc0f8940ec41242fd90131f85b834",
      "security-events-c2test-2026.10.26/801e17169c5084164bbab3f69af74b03cf7be1d2978b8bba3d7d9e03fe1fdbe3",
      "security-events-c2test-2026.10.26/ceb00f7b0f3bfd09cafa51b0d8fcd0d36b86d8ac5d727dbeb20e7a4dc7364aef",
      "security-events-c2test-2026.10.26/b0c84847fa07ca6066f66314d440284875e32fdc2e9a91147b20e64ed8802a3f",
      "security-events-c2test-2026.10.26/ab70081a885e3022b5e2b151b5d8a8c92bac1625eb8e7ff13ccd58be56c8ed25",
      "security-events-c2test-2026.10.26/78e8422fd0ca0f83f9df422f761cd287c6f0735176028d4d07ffbada484bb58c",
      "security-events-c2test-2026.10.26/281b5dda0c06d3be35b55667df065d7038d5008efccba1aeef01e62b793a7332",
      "security-events-c2test-2026.10.26/55145a5ab511dd47d1e5c61e8f7ce2c121255f4438a4dd58fb545a80eee939cb",
      "security-events-c2test-2026.10.26/12942143493b7e019bab8e878e423e657fb46dbd7c3f740272317415fc61ac05",
      "security-events-c2test-2026.10.26/e014e9d1f0589e5c51a52f73e94cd3f6051c8ce88d41126f8718763528eb4d20",
      "security-events-c2test-2026.10.26/8267a74c34ecc1d12de86fc3dfa29152cb7a48af5408855b7a55f414e363a210",
      "security-events-c2test-2026.10.26/6f055617fd9ebd441a5ea7b690a04df632339e1e1b4070717ade01151d867154",
      "security-events-c2test-2026.10.26/a71f3687021cbf3956949c00a569851771e51d0325de425beb9714223b55d2fa",
      "security-events-c2test-2026.10.26/e2149dc8d08b9bbb1a6185f659e8b3fef4f87ad8fe0c3e2358d6520bd3c7c223",
      "security-events-c2test-2026.10.26/be3796692c4c5b816ee275b5ebbcca1ba0fe02eae4a4364236fa520ed0b81ec7",
      "security-events-c2test-2026.10.26/d875c2fa0eabdfc0e87b76423c88950a640108dbf1cc6a4832c9ea2fef72b405"
    ],
    "evidence_ids": [
      "E-T1110-a",
      "E-T1110-a-dd-203.0.113.99"
    ],
    "facts": {
      "bucket_key": "203.0.113.99",
      "count": "30"
    },
    "first_seen": "2026-10-25T00:10:00.000Z",
    "kind": "aggregate",
    "origin": "playbook",
    "replay": {
      "bucket_key": "203.0.113.99",
      "count": 30,
      "distinct": null,
      "event_field": "source.ip",
      "params": {
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
      "sum": null,
      "tool": "aggregate"
    },
    "status": "self_checked",
    "step_id": "T1110-a",
    "technique": "T1110",
    "text": "Source 203.0.113.99 produced 30 failed SSH logins",
    "verifier_notes": ""
  },
  {
    "claim_id": "C-002",
    "confidence": "medium",
    "context_only": false,
    "event_ids": [
      "security-events-c2test-2026.10.26/7cf0c3b3f067b09b940fe6e9e45b5e10027220c057d9f3efded6cb93f179ccc5"
    ],
    "evidence_ids": [
      "E-T1078-b-203.0.113.99"
    ],
    "facts": {
      "host.name": "DEMO-SSH",
      "source.ip": "203.0.113.99",
      "user.name": "demo"
    },
    "first_seen": "2026-10-25T00:11:00.000Z",
    "kind": "events",
    "origin": "playbook",
    "replay": {},
    "status": "self_checked",
    "step_id": "T1078-b-203.0.113.99",
    "technique": "T1078",
    "text": "Source 203.0.113.99 logged in successfully as demo on DEMO-SSH after its failed SSH logins began",
    "verifier_notes": ""
  },
  {
    "claim_id": "C-003",
    "confidence": "medium",
    "context_only": false,
    "event_ids": [
      "security-events-c2test-2026.10.26/a57e0c8b67ef5d90eb0e704ac64eaf239d969d0030b0c46eca8319696b221f4e",
      "security-events-c2test-2026.10.26/c5d6eb0a97fca952a5de6fe59153386ebf16d7d2ee49891f2b43de9af1030d43",
      "security-events-c2test-2026.10.26/4397d8bc44453ccff0dfc97cad262ea70fd5fef74461aa1c7b2baa3068c0b24a",
      "security-events-c2test-2026.10.26/9427c3870671bf6d79f92eec44b38ac5f36be9738c947a77d6b47d9a5c0657b5",
      "security-events-c2test-2026.10.26/1c26d821e31182b7ed37906d46a3d0c1f6befdeec1f9199e6b757d1f6e362748",
      "security-events-c2test-2026.10.26/7437ece1f2aba338a445b51a8f5051deb5d2e5a608327df266687ec03a066d62",
      "security-events-c2test-2026.10.26/a566b4df52091ab96a9689fd7b75d6a6e6e5272cc733269fb075de55e374b48c",
      "security-events-c2test-2026.10.26/973349b2ca40bc2ecc261acbad2ee5419660116bd8076d3b4de1699a9dbf6cbd",
      "security-events-c2test-2026.10.26/fc8d33d3cd7a78e4a07cc6a3a343216f1bf4f39349c15b9e4c9b29390598e0b1",
      "security-events-c2test-2026.10.26/2208186b4c033e8f8d0585b7c62e67a6aea7d3fe1ae1f93aa8f828af5a0bbb8e",
      "security-events-c2test-2026.10.26/80fdb790b3ba5a403398076a16c72f64a5c7bff83e623fe2e65e8d84925b82ce",
      "security-events-c2test-2026.10.26/37e55e177a81f58e395b43f0e3bd0ba0e5d76cf673f9e8489bb703c07e78e937",
      "security-events-c2test-2026.10.26/dbab3ff1dadea5083f3b55cc2594bc5ecaade288d0855f09b97b0d5e53ffb999",
      "security-events-c2test-2026.10.26/d82f90db6b09b5f80ce70f89015f67f1d25a21ae627d7e57920e7b709f0c5a93",
      "security-events-c2test-2026.10.26/012a4728b1f6819f4acc48210e6528c0e61fc0f8940ec41242fd90131f85b834",
      "security-events-c2test-2026.10.26/801e17169c5084164bbab3f69af74b03cf7be1d2978b8bba3d7d9e03fe1fdbe3",
      "security-events-c2test-2026.10.26/ceb00f7b0f3bfd09cafa51b0d8fcd0d36b86d8ac5d727dbeb20e7a4dc7364aef",
      "security-events-c2test-2026.10.26/b0c84847fa07ca6066f66314d440284875e32fdc2e9a91147b20e64ed8802a3f",
      "security-events-c2test-2026.10.26/ab70081a885e3022b5e2b151b5d8a8c92bac1625eb8e7ff13ccd58be56c8ed25",
      "security-events-c2test-2026.10.26/78e8422fd0ca0f83f9df422f761cd287c6f0735176028d4d07ffbada484bb58c",
      "security-events-c2test-2026.10.26/281b5dda0c06d3be35b55667df065d7038d5008efccba1aeef01e62b793a7332",
      "security-events-c2test-2026.10.26/55145a5ab511dd47d1e5c61e8f7ce2c121255f4438a4dd58fb545a80eee939cb",
      "security-events-c2test-2026.10.26/12942143493b7e019bab8e878e423e657fb46dbd7c3f740272317415fc61ac05",
      "security-events-c2test-2026.10.26/e014e9d1f0589e5c51a52f73e94cd3f6051c8ce88d41126f8718763528eb4d20",
      "security-events-c2test-2026.10.26/8267a74c34ecc1d12de86fc3dfa29152cb7a48af5408855b7a55f414e363a210",
      "security-events-c2test-2026.10.26/6f055617fd9ebd441a5ea7b690a04df632339e1e1b4070717ade01151d867154",
      "security-events-c2test-2026.10.26/a71f3687021cbf3956949c00a569851771e51d0325de425beb9714223b55d2fa",
      "security-events-c2test-2026.10.26/e2149dc8d08b9bbb1a6185f659e8b3fef4f87ad8fe0c3e2358d6520bd3c7c223",
      "security-events-c2test-2026.10.26/be3796692c4c5b816ee275b5ebbcca1ba0fe02eae4a4364236fa520ed0b81ec7",
      "security-events-c2test-2026.10.26/d875c2fa0eabdfc0e87b76423c88950a640108dbf1cc6a4832c9ea2fef72b405"
    ],
    "evidence_ids": [
      "E-AG-01"
    ],
    "facts": {
      "event.outcome": "failure",
      "host.name": "DEMO-SSH",
      "source.ip": "203.0.113.99",
      "user.name": "demo"
    },
    "first_seen": "2026-10-25T00:10:00.000Z",
    "kind": "events",
    "origin": "llm",
    "replay": {},
    "status": "self_checked",
    "step_id": "AG-01",
    "technique": "T1078",
    "text": "Source 203.0.113.99 kept authenticating against DEMO-SSH with user demo after the successful login, outcome failure",
    "verifier_notes": ""
  },
  {
    "claim_id": "C-004",
    "confidence": "medium",
    "context_only": false,
    "event_ids": [
      "security-events-c2test-2026.10.26/7cf0c3b3f067b09b940fe6e9e45b5e10027220c057d9f3efded6cb93f179ccc5"
    ],
    "evidence_ids": [
      "E-AG-01"
    ],
    "facts": {
      "event.outcome": "success",
      "host.name": "DEMO-SSH",
      "source.ip": "203.0.113.99",
      "user.name": "demo"
    },
    "first_seen": "2026-10-25T00:11:00.000Z",
    "kind": "events",
    "origin": "llm",
    "replay": {},
    "status": "self_checked",
    "step_id": "AG-01",
    "technique": "T1078",
    "text": "Source 203.0.113.99 kept authenticating against DEMO-SSH with user demo after the successful login, outcome success",
    "verifier_notes": ""
  }
]
```
**Run B**
```json
[
  {
    "claim_id": "C-001",
    "confidence": "medium",
    "context_only": false,
    "event_ids": [
      "security-events-c2test-2026.10.26/a57e0c8b67ef5d90eb0e704ac64eaf239d969d0030b0c46eca8319696b221f4e",
      "security-events-c2test-2026.10.26/c5d6eb0a97fca952a5de6fe59153386ebf16d7d2ee49891f2b43de9af1030d43",
      "security-events-c2test-2026.10.26/4397d8bc44453ccff0dfc97cad262ea70fd5fef74461aa1c7b2baa3068c0b24a",
      "security-events-c2test-2026.10.26/9427c3870671bf6d79f92eec44b38ac5f36be9738c947a77d6b47d9a5c0657b5",
      "security-events-c2test-2026.10.26/1c26d821e31182b7ed37906d46a3d0c1f6befdeec1f9199e6b757d1f6e362748",
      "security-events-c2test-2026.10.26/7437ece1f2aba338a445b51a8f5051deb5d2e5a608327df266687ec03a066d62",
      "security-events-c2test-2026.10.26/a566b4df52091ab96a9689fd7b75d6a6e6e5272cc733269fb075de55e374b48c",
      "security-events-c2test-2026.10.26/973349b2ca40bc2ecc261acbad2ee5419660116bd8076d3b4de1699a9dbf6cbd",
      "security-events-c2test-2026.10.26/fc8d33d3cd7a78e4a07cc6a3a343216f1bf4f39349c15b9e4c9b29390598e0b1",
      "security-events-c2test-2026.10.26/2208186b4c033e8f8d0585b7c62e67a6aea7d3fe1ae1f93aa8f828af5a0bbb8e",
      "security-events-c2test-2026.10.26/80fdb790b3ba5a403398076a16c72f64a5c7bff83e623fe2e65e8d84925b82ce",
      "security-events-c2test-2026.10.26/37e55e177a81f58e395b43f0e3bd0ba0e5d76cf673f9e8489bb703c07e78e937",
      "security-events-c2test-2026.10.26/dbab3ff1dadea5083f3b55cc2594bc5ecaade288d0855f09b97b0d5e53ffb999",
      "security-events-c2test-2026.10.26/d82f90db6b09b5f80ce70f89015f67f1d25a21ae627d7e57920e7b709f0c5a93",
      "security-events-c2test-2026.10.26/012a4728b1f6819f4acc48210e6528c0e61fc0f8940ec41242fd90131f85b834",
      "security-events-c2test-2026.10.26/801e17169c5084164bbab3f69af74b03cf7be1d2978b8bba3d7d9e03fe1fdbe3",
      "security-events-c2test-2026.10.26/ceb00f7b0f3bfd09cafa51b0d8fcd0d36b86d8ac5d727dbeb20e7a4dc7364aef",
      "security-events-c2test-2026.10.26/b0c84847fa07ca6066f66314d440284875e32fdc2e9a91147b20e64ed8802a3f",
      "security-events-c2test-2026.10.26/ab70081a885e3022b5e2b151b5d8a8c92bac1625eb8e7ff13ccd58be56c8ed25",
      "security-events-c2test-2026.10.26/78e8422fd0ca0f83f9df422f761cd287c6f0735176028d4d07ffbada484bb58c",
      "security-events-c2test-2026.10.26/281b5dda0c06d3be35b55667df065d7038d5008efccba1aeef01e62b793a7332",
      "security-events-c2test-2026.10.26/55145a5ab511dd47d1e5c61e8f7ce2c121255f4438a4dd58fb545a80eee939cb",
      "security-events-c2test-2026.10.26/12942143493b7e019bab8e878e423e657fb46dbd7c3f740272317415fc61ac05",
      "security-events-c2test-2026.10.26/e014e9d1f0589e5c51a52f73e94cd3f6051c8ce88d41126f8718763528eb4d20",
      "security-events-c2test-2026.10.26/8267a74c34ecc1d12de86fc3dfa29152cb7a48af5408855b7a55f414e363a210",
      "security-events-c2test-2026.10.26/6f055617fd9ebd441a5ea7b690a04df632339e1e1b4070717ade01151d867154",
      "security-events-c2test-2026.10.26/a71f3687021cbf3956949c00a569851771e51d0325de425beb9714223b55d2fa",
      "security-events-c2test-2026.10.26/e2149dc8d08b9bbb1a6185f659e8b3fef4f87ad8fe0c3e2358d6520bd3c7c223",
      "security-events-c2test-2026.10.26/be3796692c4c5b816ee275b5ebbcca1ba0fe02eae4a4364236fa520ed0b81ec7",
      "security-events-c2test-2026.10.26/d875c2fa0eabdfc0e87b76423c88950a640108dbf1cc6a4832c9ea2fef72b405"
    ],
    "evidence_ids": [
      "E-T1110-a",
      "E-T1110-a-dd-203.0.113.99"
    ],
    "facts": {
      "bucket_key": "203.0.113.99",
      "count": "30"
    },
    "first_seen": "2026-10-25T00:10:00.000Z",
    "kind": "aggregate",
    "origin": "playbook",
    "replay": {
      "bucket_key": "203.0.113.99",
      "count": 30,
      "distinct": null,
      "event_field": "source.ip",
      "params": {
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
      "sum": null,
      "tool": "aggregate"
    },
    "status": "self_checked",
    "step_id": "T1110-a",
    "technique": "T1110",
    "text": "Source 203.0.113.99 produced 30 failed SSH logins",
    "verifier_notes": ""
  },
  {
    "claim_id": "C-002",
    "confidence": "medium",
    "context_only": false,
    "event_ids": [
      "security-events-c2test-2026.10.26/7cf0c3b3f067b09b940fe6e9e45b5e10027220c057d9f3efded6cb93f179ccc5"
    ],
    "evidence_ids": [
      "E-T1078-b-203.0.113.99"
    ],
    "facts": {
      "host.name": "DEMO-SSH",
      "source.ip": "203.0.113.99",
      "user.name": "demo"
    },
    "first_seen": "2026-10-25T00:11:00.000Z",
    "kind": "events",
    "origin": "playbook",
    "replay": {},
    "status": "self_checked",
    "step_id": "T1078-b-203.0.113.99",
    "technique": "T1078",
    "text": "Source 203.0.113.99 logged in successfully as demo on DEMO-SSH after its failed SSH logins began",
    "verifier_notes": ""
  },
  {
    "claim_id": "C-003",
    "confidence": "medium",
    "context_only": false,
    "event_ids": [
      "security-events-c2test-2026.10.26/7cf0c3b3f067b09b940fe6e9e45b5e10027220c057d9f3efded6cb93f179ccc5"
    ],
    "evidence_ids": [
      "E-AG-01"
    ],
    "facts": {
      "host.name": "DEMO-SSH",
      "source.ip": "203.0.113.99",
      "user.name": "demo"
    },
    "first_seen": "2026-10-25T00:11:00.000Z",
    "kind": "events",
    "origin": "llm",
    "replay": {},
    "status": "self_checked",
    "step_id": "AG-01",
    "technique": "T1078",
    "text": "Successful SSH login as demo from 203.0.113.99",
    "verifier_notes": ""
  }
]
```

### evidence_contents

**Run A**
```json
[
  {
    "event_ids": [],
    "evidence_id": "E-T1110-a",
    "excerpt": [
      {
        "count": 30,
        "key": "203.0.113.99"
      }
    ],
    "index": "security-events-c2test*",
    "step_id": "T1110-a",
    "total_hits": 30
  },
  {
    "event_ids": [
      "security-events-c2test-2026.10.26/a57e0c8b67ef5d90eb0e704ac64eaf239d969d0030b0c46eca8319696b221f4e",
      "security-events-c2test-2026.10.26/c5d6eb0a97fca952a5de6fe59153386ebf16d7d2ee49891f2b43de9af1030d43",
      "security-events-c2test-2026.10.26/4397d8bc44453ccff0dfc97cad262ea70fd5fef74461aa1c7b2baa3068c0b24a",
      "security-events-c2test-2026.10.26/9427c3870671bf6d79f92eec44b38ac5f36be9738c947a77d6b47d9a5c0657b5",
      "security-events-c2test-2026.10.26/1c26d821e31182b7ed37906d46a3d0c1f6befdeec1f9199e6b757d1f6e362748",
      "security-events-c2test-2026.10.26/7437ece1f2aba338a445b51a8f5051deb5d2e5a608327df266687ec03a066d62",
      "security-events-c2test-2026.10.26/a566b4df52091ab96a9689fd7b75d6a6e6e5272cc733269fb075de55e374b48c",
      "security-events-c2test-2026.10.26/973349b2ca40bc2ecc261acbad2ee5419660116bd8076d3b4de1699a9dbf6cbd",
      "security-events-c2test-2026.10.26/fc8d33d3cd7a78e4a07cc6a3a343216f1bf4f39349c15b9e4c9b29390598e0b1",
      "security-events-c2test-2026.10.26/2208186b4c033e8f8d0585b7c62e67a6aea7d3fe1ae1f93aa8f828af5a0bbb8e",
      "security-events-c2test-2026.10.26/80fdb790b3ba5a403398076a16c72f64a5c7bff83e623fe2e65e8d84925b82ce",
      "security-events-c2test-2026.10.26/37e55e177a81f58e395b43f0e3bd0ba0e5d76cf673f9e8489bb703c07e78e937",
      "security-events-c2test-2026.10.26/dbab3ff1dadea5083f3b55cc2594bc5ecaade288d0855f09b97b0d5e53ffb999",
      "security-events-c2test-2026.10.26/d82f90db6b09b5f80ce70f89015f67f1d25a21ae627d7e57920e7b709f0c5a93",
      "security-events-c2test-2026.10.26/012a4728b1f6819f4acc48210e6528c0e61fc0f8940ec41242fd90131f85b834",
      "security-events-c2test-2026.10.26/801e17169c5084164bbab3f69af74b03cf7be1d2978b8bba3d7d9e03fe1fdbe3",
      "security-events-c2test-2026.10.26/ceb00f7b0f3bfd09cafa51b0d8fcd0d36b86d8ac5d727dbeb20e7a4dc7364aef",
      "security-events-c2test-2026.10.26/b0c84847fa07ca6066f66314d440284875e32fdc2e9a91147b20e64ed8802a3f",
      "security-events-c2test-2026.10.26/ab70081a885e3022b5e2b151b5d8a8c92bac1625eb8e7ff13ccd58be56c8ed25",
      "security-events-c2test-2026.10.26/78e8422fd0ca0f83f9df422f761cd287c6f0735176028d4d07ffbada484bb58c",
      "security-events-c2test-2026.10.26/281b5dda0c06d3be35b55667df065d7038d5008efccba1aeef01e62b793a7332",
      "security-events-c2test-2026.10.26/55145a5ab511dd47d1e5c61e8f7ce2c121255f4438a4dd58fb545a80eee939cb",
      "security-events-c2test-2026.10.26/12942143493b7e019bab8e878e423e657fb46dbd7c3f740272317415fc61ac05",
      "security-events-c2test-2026.10.26/e014e9d1f0589e5c51a52f73e94cd3f6051c8ce88d41126f8718763528eb4d20",
      "security-events-c2test-2026.10.26/8267a74c34ecc1d12de86fc3dfa29152cb7a48af5408855b7a55f414e363a210",
      "security-events-c2test-2026.10.26/6f055617fd9ebd441a5ea7b690a04df632339e1e1b4070717ade01151d867154",
      "security-events-c2test-2026.10.26/a71f3687021cbf3956949c00a569851771e51d0325de425beb9714223b55d2fa",
      "security-events-c2test-2026.10.26/e2149dc8d08b9bbb1a6185f659e8b3fef4f87ad8fe0c3e2358d6520bd3c7c223",
      "security-events-c2test-2026.10.26/be3796692c4c5b816ee275b5ebbcca1ba0fe02eae4a4364236fa520ed0b81ec7",
      "security-events-c2test-2026.10.26/d875c2fa0eabdfc0e87b76423c88950a640108dbf1cc6a4832c9ea2fef72b405"
    ],
    "evidence_id": "E-T1110-a-dd-203.0.113.99",
    "excerpt": [
      {
        "@timestamp": "2026-10-25T00:10:00.000Z",
        "source.ip": "203.0.113.99"
      },
      {
        "@timestamp": "2026-10-25T00:10:01.000Z",
        "source.ip": "203.0.113.99"
      },
      {
        "@timestamp": "2026-10-25T00:10:02.000Z",
        "source.ip": "203.0.113.99"
      }
    ],
    "index": "security-events-c2test*",
    "step_id": "T1110-a-dd-203.0.113.99",
    "total_hits": 30
  },
  {
    "event_ids": [],
    "evidence_id": "E-T1078-a",
    "excerpt": [
      {
        "count": 30,
        "key": "203.0.113.99"
      }
    ],
    "index": "security-events-c2test*",
    "step_id": "T1078-a",
    "total_hits": 30
  },
  {
    "event_ids": [
      "security-events-c2test-2026.10.26/a57e0c8b67ef5d90eb0e704ac64eaf239d969d0030b0c46eca8319696b221f4e"
    ],
    "evidence_id": "E-T1078-first-203.0.113.99",
    "excerpt": [
      {
        "@timestamp": "2026-10-25T00:10:00.000Z"
      }
    ],
    "index": "security-events-c2test*",
    "step_id": "T1078-first-203.0.113.99",
    "total_hits": 30
  },
  {
    "event_ids": [
      "security-events-c2test-2026.10.26/7cf0c3b3f067b09b940fe6e9e45b5e10027220c057d9f3efded6cb93f179ccc5"
    ],
    "evidence_id": "E-T1078-b-203.0.113.99",
    "excerpt": [
      {
        "@timestamp": "2026-10-25T00:11:00.000Z",
        "host.name": "DEMO-SSH",
        "source.ip": "203.0.113.99",
        "user.name": "demo"
      }
    ],
    "index": "security-events-c2test*",
    "step_id": "T1078-b-203.0.113.99",
    "total_hits": 1
  },
  {
    "event_ids": [
      "security-events-c2test-2026.10.26/a57e0c8b67ef5d90eb0e704ac64eaf239d969d0030b0c46eca8319696b221f4e",
      "security-events-c2test-2026.10.26/c5d6eb0a97fca952a5de6fe59153386ebf16d7d2ee49891f2b43de9af1030d43",
      "security-events-c2test-2026.10.26/4397d8bc44453ccff0dfc97cad262ea70fd5fef74461aa1c7b2baa3068c0b24a",
      "security-events-c2test-2026.10.26/9427c3870671bf6d79f92eec44b38ac5f36be9738c947a77d6b47d9a5c0657b5",
      "security-events-c2test-2026.10.26/1c26d821e31182b7ed37906d46a3d0c1f6befdeec1f9199e6b757d1f6e362748",
      "security-events-c2test-2026.10.26/7437ece1f2aba338a445b51a8f5051deb5d2e5a608327df266687ec03a066d62",
      "security-events-c2test-2026.10.26/a566b4df52091ab96a9689fd7b75d6a6e6e5272cc733269fb075de55e374b48c",
      "security-events-c2test-2026.10.26/973349b2ca40bc2ecc261acbad2ee5419660116bd8076d3b4de1699a9dbf6cbd",
      "security-events-c2test-2026.10.26/fc8d33d3cd7a78e4a07cc6a3a343216f1bf4f39349c15b9e4c9b29390598e0b1",
      "security-events-c2test-2026.10.26/2208186b4c033e8f8d0585b7c62e67a6aea7d3fe1ae1f93aa8f828af5a0bbb8e",
      "security-events-c2test-2026.10.26/80fdb790b3ba5a403398076a16c72f64a5c7bff83e623fe2e65e8d84925b82ce",
      "security-events-c2test-2026.10.26/37e55e177a81f58e395b43f0e3bd0ba0e5d76cf673f9e8489bb703c07e78e937",
      "security-events-c2test-2026.10.26/dbab3ff1dadea5083f3b55cc2594bc5ecaade288d0855f09b97b0d5e53ffb999",
      "security-events-c2test-2026.10.26/d82f90db6b09b5f80ce70f89015f67f1d25a21ae627d7e57920e7b709f0c5a93",
      "security-events-c2test-2026.10.26/012a4728b1f6819f4acc48210e6528c0e61fc0f8940ec41242fd90131f85b834",
      "security-events-c2test-2026.10.26/801e17169c5084164bbab3f69af74b03cf7be1d2978b8bba3d7d9e03fe1fdbe3",
      "security-events-c2test-2026.10.26/ceb00f7b0f3bfd09cafa51b0d8fcd0d36b86d8ac5d727dbeb20e7a4dc7364aef",
      "security-events-c2test-2026.10.26/b0c84847fa07ca6066f66314d440284875e32fdc2e9a91147b20e64ed8802a3f",
      "security-events-c2test-2026.10.26/ab70081a885e3022b5e2b151b5d8a8c92bac1625eb8e7ff13ccd58be56c8ed25",
      "security-events-c2test-2026.10.26/78e8422fd0ca0f83f9df422f761cd287c6f0735176028d4d07ffbada484bb58c",
      "security-events-c2test-2026.10.26/281b5dda0c06d3be35b55667df065d7038d5008efccba1aeef01e62b793a7332",
      "security-events-c2test-2026.10.26/55145a5ab511dd47d1e5c61e8f7ce2c121255f4438a4dd58fb545a80eee939cb",
      "security-events-c2test-2026.10.26/12942143493b7e019bab8e878e423e657fb46dbd7c3f740272317415fc61ac05",
      "security-events-c2test-2026.10.26/e014e9d1f0589e5c51a52f73e94cd3f6051c8ce88d41126f8718763528eb4d20",
      "security-events-c2test-2026.10.26/8267a74c34ecc1d12de86fc3dfa29152cb7a48af5408855b7a55f414e363a210",
      "security-events-c2test-2026.10.26/6f055617fd9ebd441a5ea7b690a04df632339e1e1b4070717ade01151d867154",
      "security-events-c2test-2026.10.26/a71f3687021cbf3956949c00a569851771e51d0325de425beb9714223b55d2fa",
      "security-events-c2test-2026.10.26/e2149dc8d08b9bbb1a6185f659e8b3fef4f87ad8fe0c3e2358d6520bd3c7c223",
      "security-events-c2test-2026.10.26/be3796692c4c5b816ee275b5ebbcca1ba0fe02eae4a4364236fa520ed0b81ec7",
      "security-events-c2test-2026.10.26/d875c2fa0eabdfc0e87b76423c88950a640108dbf1cc6a4832c9ea2fef72b405",
      "security-events-c2test-2026.10.26/7cf0c3b3f067b09b940fe6e9e45b5e10027220c057d9f3efded6cb93f179ccc5"
    ],
    "evidence_id": "E-AG-01",
    "excerpt": [
      {
        "@timestamp": "2026-10-25T00:10:00.000Z",
        "event.action": "ssh_login",
        "event.outcome": "failure",
        "host.name": "DEMO-SSH",
        "message": "2026-10-25T00:10:00Z DEMO-SSH sshd[123]: Failed password for demo from 203.0.113.99 port 40000 ssh2",
        "process.name": "sshd",
        "source.ip": "203.0.113.99",
        "source.port": 40000,
        "user.name": "demo"
      },
      {
        "@timestamp": "2026-10-25T00:10:01.000Z",
        "event.action": "ssh_login",
        "event.outcome": "failure",
        "host.name": "DEMO-SSH",
        "message": "2026-10-25T00:10:01Z DEMO-SSH sshd[123]: Failed password for demo from 203.0.113.99 port 40001 ssh2",
        "process.name": "sshd",
        "source.ip": "203.0.113.99",
        "source.port": 40001,
        "user.name": "demo"
      },
      {
        "@timestamp": "2026-10-25T00:10:02.000Z",
        "event.action": "ssh_login",
        "event.outcome": "failure",
        "host.name": "DEMO-SSH",
        "message": "2026-10-25T00:10:02Z DEMO-SSH sshd[123]: Failed password for demo from 203.0.113.99 port 40002 ssh2",
        "process.name": "sshd",
        "source.ip": "203.0.113.99",
        "source.port": 40002,
        "user.name": "demo"
      }
    ],
    "index": "security-events-c2test*",
    "step_id": "AG-01",
    "total_hits": 31
  },
  {
    "event_ids": [
      "security-events-c2test-2026.10.26/7cf0c3b3f067b09b940fe6e9e45b5e10027220c057d9f3efded6cb93f179ccc5"
    ],
    "evidence_id": "E-AG-02",
    "excerpt": [
      {
        "@timestamp": "2026-10-25T00:11:00.000Z",
        "event.action": "ssh_login",
        "event.outcome": "success",
        "host.name": "DEMO-SSH",
        "message": "2026-10-25T00:11:00Z DEMO-SSH sshd[123]: Accepted password for demo from 203.0.113.99 port 41000 ssh2",
        "source.ip": "203.0.113.99",
        "source.port": 41000,
        "user.name": "demo"
      }
    ],
    "index": "security-events-c2test*",
    "step_id": "AG-02",
    "total_hits": 1
  },
  {
    "event_ids": [],
    "evidence_id": "E-SK-01",
    "excerpt": [],
    "index": "security-events-c2test*",
    "step_id": "SK-01",
    "total_hits": 0
  },
  {
    "event_ids": [],
    "evidence_id": "E-SK-02",
    "excerpt": [],
    "index": "security-events-c2test*",
    "step_id": "SK-02",
    "total_hits": 31
  },
  {
    "event_ids": [],
    "evidence_id": "E-SK-03",
    "excerpt": [],
    "index": "security-events-c2test*",
    "step_id": "SK-03",
    "total_hits": 0
  },
  {
    "event_ids": [],
    "evidence_id": "E-SK-04",
    "excerpt": [
      {
        "count": 0,
        "key": "2026-10-18T00:00:00.000Z"
      },
      {
        "count": 0,
        "key": "2026-10-19T00:00:00.000Z"
      },
      {
        "count": 0,
        "key": "2026-10-20T00:00:00.000Z"
      },
      {
        "count": 0,
        "key": "2026-10-21T00:00:00.000Z"
      },
      {
        "count": 0,
        "key": "2026-10-22T00:00:00.000Z"
      }
    ],
    "index": "security-events-c2test*",
    "step_id": "SK-04",
    "total_hits": 0
  }
]
```
**Run B**
```json
[
  {
    "event_ids": [],
    "evidence_id": "E-T1110-a",
    "excerpt": [
      {
        "count": 30,
        "key": "203.0.113.99"
      }
    ],
    "index": "security-events-c2test*",
    "step_id": "T1110-a",
    "total_hits": 30
  },
  {
    "event_ids": [
      "security-events-c2test-2026.10.26/a57e0c8b67ef5d90eb0e704ac64eaf239d969d0030b0c46eca8319696b221f4e",
      "security-events-c2test-2026.10.26/c5d6eb0a97fca952a5de6fe59153386ebf16d7d2ee49891f2b43de9af1030d43",
      "security-events-c2test-2026.10.26/4397d8bc44453ccff0dfc97cad262ea70fd5fef74461aa1c7b2baa3068c0b24a",
      "security-events-c2test-2026.10.26/9427c3870671bf6d79f92eec44b38ac5f36be9738c947a77d6b47d9a5c0657b5",
      "security-events-c2test-2026.10.26/1c26d821e31182b7ed37906d46a3d0c1f6befdeec1f9199e6b757d1f6e362748",
      "security-events-c2test-2026.10.26/7437ece1f2aba338a445b51a8f5051deb5d2e5a608327df266687ec03a066d62",
      "security-events-c2test-2026.10.26/a566b4df52091ab96a9689fd7b75d6a6e6e5272cc733269fb075de55e374b48c",
      "security-events-c2test-2026.10.26/973349b2ca40bc2ecc261acbad2ee5419660116bd8076d3b4de1699a9dbf6cbd",
      "security-events-c2test-2026.10.26/fc8d33d3cd7a78e4a07cc6a3a343216f1bf4f39349c15b9e4c9b29390598e0b1",
      "security-events-c2test-2026.10.26/2208186b4c033e8f8d0585b7c62e67a6aea7d3fe1ae1f93aa8f828af5a0bbb8e",
      "security-events-c2test-2026.10.26/80fdb790b3ba5a403398076a16c72f64a5c7bff83e623fe2e65e8d84925b82ce",
      "security-events-c2test-2026.10.26/37e55e177a81f58e395b43f0e3bd0ba0e5d76cf673f9e8489bb703c07e78e937",
      "security-events-c2test-2026.10.26/dbab3ff1dadea5083f3b55cc2594bc5ecaade288d0855f09b97b0d5e53ffb999",
      "security-events-c2test-2026.10.26/d82f90db6b09b5f80ce70f89015f67f1d25a21ae627d7e57920e7b709f0c5a93",
      "security-events-c2test-2026.10.26/012a4728b1f6819f4acc48210e6528c0e61fc0f8940ec41242fd90131f85b834",
      "security-events-c2test-2026.10.26/801e17169c5084164bbab3f69af74b03cf7be1d2978b8bba3d7d9e03fe1fdbe3",
      "security-events-c2test-2026.10.26/ceb00f7b0f3bfd09cafa51b0d8fcd0d36b86d8ac5d727dbeb20e7a4dc7364aef",
      "security-events-c2test-2026.10.26/b0c84847fa07ca6066f66314d440284875e32fdc2e9a91147b20e64ed8802a3f",
      "security-events-c2test-2026.10.26/ab70081a885e3022b5e2b151b5d8a8c92bac1625eb8e7ff13ccd58be56c8ed25",
      "security-events-c2test-2026.10.26/78e8422fd0ca0f83f9df422f761cd287c6f0735176028d4d07ffbada484bb58c",
      "security-events-c2test-2026.10.26/281b5dda0c06d3be35b55667df065d7038d5008efccba1aeef01e62b793a7332",
      "security-events-c2test-2026.10.26/55145a5ab511dd47d1e5c61e8f7ce2c121255f4438a4dd58fb545a80eee939cb",
      "security-events-c2test-2026.10.26/12942143493b7e019bab8e878e423e657fb46dbd7c3f740272317415fc61ac05",
      "security-events-c2test-2026.10.26/e014e9d1f0589e5c51a52f73e94cd3f6051c8ce88d41126f8718763528eb4d20",
      "security-events-c2test-2026.10.26/8267a74c34ecc1d12de86fc3dfa29152cb7a48af5408855b7a55f414e363a210",
      "security-events-c2test-2026.10.26/6f055617fd9ebd441a5ea7b690a04df632339e1e1b4070717ade01151d867154",
      "security-events-c2test-2026.10.26/a71f3687021cbf3956949c00a569851771e51d0325de425beb9714223b55d2fa",
      "security-events-c2test-2026.10.26/e2149dc8d08b9bbb1a6185f659e8b3fef4f87ad8fe0c3e2358d6520bd3c7c223",
      "security-events-c2test-2026.10.26/be3796692c4c5b816ee275b5ebbcca1ba0fe02eae4a4364236fa520ed0b81ec7",
      "security-events-c2test-2026.10.26/d875c2fa0eabdfc0e87b76423c88950a640108dbf1cc6a4832c9ea2fef72b405"
    ],
    "evidence_id": "E-T1110-a-dd-203.0.113.99",
    "excerpt": [
      {
        "@timestamp": "2026-10-25T00:10:00.000Z",
        "source.ip": "203.0.113.99"
      },
      {
        "@timestamp": "2026-10-25T00:10:01.000Z",
        "source.ip": "203.0.113.99"
      },
      {
        "@timestamp": "2026-10-25T00:10:02.000Z",
        "source.ip": "203.0.113.99"
      }
    ],
    "index": "security-events-c2test*",
    "step_id": "T1110-a-dd-203.0.113.99",
    "total_hits": 30
  },
  {
    "event_ids": [],
    "evidence_id": "E-T1078-a",
    "excerpt": [
      {
        "count": 30,
        "key": "203.0.113.99"
      }
    ],
    "index": "security-events-c2test*",
    "step_id": "T1078-a",
    "total_hits": 30
  },
  {
    "event_ids": [
      "security-events-c2test-2026.10.26/a57e0c8b67ef5d90eb0e704ac64eaf239d969d0030b0c46eca8319696b221f4e"
    ],
    "evidence_id": "E-T1078-first-203.0.113.99",
    "excerpt": [
      {
        "@timestamp": "2026-10-25T00:10:00.000Z"
      }
    ],
    "index": "security-events-c2test*",
    "step_id": "T1078-first-203.0.113.99",
    "total_hits": 30
  },
  {
    "event_ids": [
      "security-events-c2test-2026.10.26/7cf0c3b3f067b09b940fe6e9e45b5e10027220c057d9f3efded6cb93f179ccc5"
    ],
    "evidence_id": "E-T1078-b-203.0.113.99",
    "excerpt": [
      {
        "@timestamp": "2026-10-25T00:11:00.000Z",
        "host.name": "DEMO-SSH",
        "source.ip": "203.0.113.99",
        "user.name": "demo"
      }
    ],
    "index": "security-events-c2test*",
    "step_id": "T1078-b-203.0.113.99",
    "total_hits": 1
  },
  {
    "event_ids": [
      "security-events-c2test-2026.10.26/7cf0c3b3f067b09b940fe6e9e45b5e10027220c057d9f3efded6cb93f179ccc5"
    ],
    "evidence_id": "E-AG-01",
    "excerpt": [
      {
        "@timestamp": "2026-10-25T00:11:00.000Z",
        "event.action": "ssh_login",
        "event.outcome": "success",
        "host.name": "DEMO-SSH",
        "source.ip": "203.0.113.99",
        "source.port": 41000,
        "user.name": "demo"
      }
    ],
    "index": "security-events-c2test*",
    "step_id": "AG-01",
    "total_hits": 1
  },
  {
    "event_ids": [],
    "evidence_id": "E-SK-01",
    "excerpt": [],
    "index": "security-events-c2test*",
    "step_id": "SK-01",
    "total_hits": 0
  },
  {
    "event_ids": [],
    "evidence_id": "E-SK-02",
    "excerpt": [
      {
        "value": 1
      }
    ],
    "index": "security-events-c2test*",
    "step_id": "SK-02",
    "total_hits": 31
  },
  {
    "event_ids": [],
    "evidence_id": "E-SK-03",
    "excerpt": [
      {
        "count": 1,
        "key": "198.51.100.20"
      },
      {
        "count": 1,
        "key": "203.0.113.99"
      }
    ],
    "index": "security-events-c2test*",
    "step_id": "SK-03",
    "total_hits": 2
  },
  {
    "event_ids": [],
    "evidence_id": "E-SK-04",
    "excerpt": [
      {
        "value": 1
      }
    ],
    "index": "security-events-c2test*",
    "step_id": "SK-04",
    "total_hits": 1
  }
]
```

### queries_and_values

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
              "term": {
                "event.dataset": {
                  "case_insensitive": true,
                  "value": "linux.auth"
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
            },
            {
              "term": {
                "source.ip": "203.0.113.99"
              }
            }
          ]
        }
      },
      "size": 60,
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
    "phase": "agent",
    "purpose": "All linux.auth events on DEMO-SSH from 203.0.113.99 at and after the first failed login, ordered in time, to see the fail-then-success sequence and any post-success authentication activity",
    "request": {
      "fields": [
        "@timestamp",
        "destination.port",
        "event.action",
        "event.outcome",
        "event.type",
        "host.name",
        "message",
        "process.name",
        "source.ip",
        "source.port",
        "user.name"
      ],
      "filters": [
        {
          "field": "event.dataset",
          "op": "eq",
          "value": "linux.auth"
        },
        {
          "field": "host.name",
          "op": "eq",
          "value": "DEMO-SSH"
        },
        {
          "field": "source.ip",
          "op": "eq",
          "value": "203.0.113.99"
        }
      ],
      "index": "security-events-c2test*",
      "size": 60,
      "time_from": "2026-10-25T00:10:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "631e1f78011c95ae2fd6fb2cdd8e00429fee6660f16d5968480d3825a04b4c65",
    "seq": 17,
    "server": "es",
    "step_id": "AG-01",
    "tool": "search",
    "total": 31
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
                "event.dataset": {
                  "case_insensitive": true,
                  "value": "linux.auth"
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
    "phase": "agent",
    "purpose": "Successful SSH logins on DEMO-SSH in the hunt window: timestamp, source.ip, user.name and raw message, to confirm the success from 203.0.113.99 followed the failure burst and that no other source or a...",
    "request": {
      "fields": [
        "@timestamp",
        "host.name",
        "source.ip",
        "source.port",
        "user.name",
        "event.action",
        "event.outcome",
        "message"
      ],
      "filters": [
        {
          "field": "event.dataset",
          "op": "eq",
          "value": "linux.auth"
        },
        {
          "field": "host.name",
          "op": "eq",
          "value": "DEMO-SSH"
        },
        {
          "field": "event.outcome",
          "op": "eq",
          "value": "success"
        }
      ],
      "index": "security-events-c2test*",
      "size": 20,
      "time_from": "2026-10-25T00:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "57da340ef4c3447e818646df2378007a25a020686e5878e95fe1107606db7e01",
    "seq": 18,
    "server": "es",
    "step_id": "AG-02",
    "tool": "search",
    "total": 1
  },
  {
    "dsl": {
      "aggs": {
        "a": {
          "terms": {
            "field": "host.name",
            "size": 100
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
                "event.dataset": {
                  "case_insensitive": true,
                  "value": "linux.auth"
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
    "purpose": "Check whether 203.0.113.99 produced failed SSH logins on prior days, which would support a recurring job with stale credentials rather than a one-off brute force.",
    "request": {
      "agg": "terms",
      "field": "host.name",
      "filters": [
        {
          "field": "event.dataset",
          "op": "eq",
          "value": "linux.auth"
        },
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
      "size": 100,
      "time_from": "2026-10-18T00:00:00Z",
      "time_to": "2026-10-25T00:00:00Z"
    },
    "request_hash": "b93620a2bf8da9e9d2b964dd8a5ed7f949a6b6963f1460c730993b5486770387",
    "seq": 19,
    "server": "es",
    "step_id": "SK-01",
    "tool": "aggregate",
    "total": 0
  },
  {
    "dsl": {
      "aggs": {
        "a": {
          "terms": {
            "field": "destination.port",
            "size": 100
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
            }
          ]
        }
      },
      "size": 0
    },
    "ok": true,
    "phase": "skeptic",
    "purpose": "See whether the source contacted multiple destination ports in the hunt window, which is more consistent with a multi-service scanner than SSH-only brute force.",
    "request": {
      "agg": "terms",
      "field": "destination.port",
      "filters": [
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
    "request_hash": "1a2eecb35ff81c19c0497577897118bb21ee7475057db65bb125adaf5455f49c",
    "seq": 20,
    "server": "es",
    "step_id": "SK-02",
    "tool": "aggregate",
    "total": 31
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
                "event.dataset": {
                  "case_insensitive": true,
                  "value": "linux.auth"
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
      }
    },
    "ok": true,
    "phase": "skeptic",
    "purpose": "Check for successful SSH logins by demo from 203.0.113.99 on prior days, which would show the successful login is routine rather than a post-brute-force compromise.",
    "request": {
      "filters": [
        {
          "field": "event.dataset",
          "op": "eq",
          "value": "linux.auth"
        },
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
      "time_from": "2026-10-18T00:00:00Z",
      "time_to": "2026-10-25T00:00:00Z"
    },
    "request_hash": "c054d1427fcefd852bf74621db849e7627e55f37d5ad5fa40869d89382d326c3",
    "seq": 21,
    "server": "es",
    "step_id": "SK-03",
    "tool": "count",
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
                "event.dataset": {
                  "case_insensitive": true,
                  "value": "linux.auth"
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
      "size": 0
    },
    "ok": true,
    "phase": "skeptic",
    "purpose": "Check whether successful demo logins from 203.0.113.99 recur across multiple prior days, which would support a scheduled automation job.",
    "request": {
      "agg": "date_histogram",
      "field": "@timestamp",
      "filters": [
        {
          "field": "event.dataset",
          "op": "eq",
          "value": "linux.auth"
        },
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
      "interval": "1d",
      "size": 100,
      "time_from": "2026-10-18T00:00:00Z",
      "time_to": "2026-10-25T00:00:00Z"
    },
    "request_hash": "1f68c9b1f1832f5f14d89c965f101e354c258b7a7f061f4b9fb1a8536d9094f3",
    "seq": 22,
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
    "seq": 23,
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
    "seq": 24,
    "server": "es",
    "step_id": null,
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
                  "gte": "2026-10-25T00:10:00.000Z",
                  "lt": "2026-10-25T01:00:00.000Z"
                }
              }
            },
            {
              "term": {
                "event.dataset": {
                  "case_insensitive": true,
                  "value": "linux.auth"
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
          "op": "eq",
          "value": "linux.auth"
        },
        {
          "field": "source.ip",
          "op": "eq",
          "value": "203.0.113.99"
        }
      ],
      "index": "security-events-c2test*",
      "size": 200,
      "time_from": "2026-10-25T00:10:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "b226f1cfd607f95e5c7ab1a6a17c157c4f23171da4fa9a66bd4f9ae28c55ac8f",
    "seq": 25,
    "server": "es",
    "step_id": null,
    "tool": "search",
    "total": 31
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
                  "gte": "2026-09-24T01:00:00.000Z",
                  "lt": "2026-10-25T01:00:00.000Z"
                }
              }
            },
            {
              "term": {
                "event.dataset": {
                  "case_insensitive": true,
                  "value": "linux.auth"
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
    "phase": "agent",
    "purpose": "All successful SSH logins on DEMO-SSH to see whether the 203.0.113.99/demo success is unique or matches a normal baseline",
    "request": {
      "fields": [
        "@timestamp",
        "event.action",
        "event.original",
        "event.outcome",
        "host.name",
        "source.ip",
        "source.port",
        "user.name"
      ],
      "filters": [
        {
          "field": "event.dataset",
          "op": "eq",
          "value": "linux.auth"
        },
        {
          "field": "host.name",
          "op": "eq",
          "value": "DEMO-SSH"
        },
        {
          "field": "event.outcome",
          "op": "eq",
          "value": "success"
        }
      ],
      "index": "security-events-c2test*",
      "size": 100,
      "time_from": "2026-09-24T01:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "7454ba5e314cb9387038a71ea371debd49007f9555cd78608857dfe2d7768e3f",
    "seq": 17,
    "server": "es",
    "step_id": "AG-01",
    "tool": "search",
    "total": 1
  },
  {
    "dsl": null,
    "ok": true,
    "phase": "agent",
    "purpose": "Check reputation of the external brute-force source 203.0.113.99",
    "request": {
      "value": "203.0.113.99"
    },
    "request_hash": "10f5b60e77b7fc652ae033411d77c5b7784d9d5da12d4c3990fece3ca7e7e0e9",
    "seq": 18,
    "server": "analytics",
    "step_id": "AG-02",
    "tool": "check_ioc",
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
                  "gte": "2026-10-24T00:00:00.000Z",
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
      }
    },
    "ok": true,
    "phase": "skeptic",
    "purpose": "Count failed SSH logins from 203.0.113.99 during the previous 24h (outside the hunt window) to see whether the same burst repeats on a schedule",
    "request": {
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
      "time_from": "2026-10-24T00:00:00Z",
      "time_to": "2026-10-25T00:00:00Z"
    },
    "request_hash": "c62244460762e7b0139a85efeec8ac28728c5e466e56e07ada5ef8ea2e2c271f",
    "seq": 19,
    "server": "es",
    "step_id": "SK-01",
    "tool": "count",
    "total": 0
  },
  {
    "dsl": {
      "aggs": {
        "a": {
          "cardinality": {
            "field": "host.name"
          }
        }
      },
      "query": {
        "bool": {
          "filter": [
            {
              "range": {
                "@timestamp": {
                  "gte": "2026-10-24T00:00:00.000Z",
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
    "purpose": "Count distinct host.name values touched by 203.0.113.99 across all datasets in the preceding 24h; many hosts indicates a scanner sweep",
    "request": {
      "agg": "cardinality",
      "field": "host.name",
      "filters": [
        {
          "field": "source.ip",
          "op": "eq",
          "value": "203.0.113.99"
        }
      ],
      "index": "security-events-c2test*",
      "size": 100,
      "time_from": "2026-10-24T00:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "0c9bebe6eaeb022cfca51c2f8be87cae32104c88172404d68be4428b0158aba8",
    "seq": 20,
    "server": "es",
    "step_id": "SK-02",
    "tool": "aggregate",
    "total": 31
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
                  "gte": "2026-10-24T00:00:00.000Z",
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
    "purpose": "List the source IPs that successfully logged in as 'demo' over the previous day; multiple distinct IPs (including internal ranges) indicate normal multi-location use of a shared account",
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
      "time_from": "2026-10-24T00:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "409a9c8f04d1802e5573724569dfc811885b9bb5841f7c0273d4402bfb185794",
    "seq": 21,
    "server": "es",
    "step_id": "SK-03",
    "tool": "aggregate",
    "total": 2
  },
  {
    "dsl": {
      "aggs": {
        "a": {
          "cardinality": {
            "field": "user.name"
          }
        }
      },
      "query": {
        "bool": {
          "filter": [
            {
              "range": {
                "@timestamp": {
                  "gte": "2026-10-24T00:00:00.000Z",
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
    "purpose": "Count distinct user.name values that successfully authenticate from 203.0.113.99 over the previous day; many users means the IP is a shared gateway rather than an attacker host",
    "request": {
      "agg": "cardinality",
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
          "value": "success"
        }
      ],
      "index": "security-events-c2test*",
      "size": 100,
      "time_from": "2026-10-24T00:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "35b02616009de023ad0724853c89934200ec16604ca10258657beae6cfb12cbe",
    "seq": 22,
    "server": "es",
    "step_id": "SK-04",
    "tool": "aggregate",
    "total": 1
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
    "seq": 23,
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
    "seq": 24,
    "server": "es",
    "step_id": null,
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
                  "gte": "2026-09-24T01:00:00.000Z",
                  "lt": "2026-10-25T01:00:00.000Z"
                }
              }
            },
            {
              "term": {
                "event.dataset": {
                  "case_insensitive": true,
                  "value": "linux.auth"
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
          "op": "eq",
          "value": "linux.auth"
        },
        {
          "field": "event.outcome",
          "op": "eq",
          "value": "success"
        }
      ],
      "index": "security-events-c2test*",
      "size": 200,
      "time_from": "2026-09-24T01:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "request_hash": "a602dffb6fc9351b3ee9faf1aa9da4c9d65570e130682253736c645c06fb7dfb",
    "seq": 25,
    "server": "es",
    "step_id": null,
    "tool": "search",
    "total": 2
  }
]
```

### actions

**Run A**
```json
{
  "detections": [
    {
      "es_query": {
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
        "size": 20,
        "time_from": "2026-10-25T00:00:00Z",
        "time_to": "2026-10-25T01:00:00Z"
      },
      "file": "actions/detections/T1110-a.yml",
      "from_step": "T1110-a",
      "host_scope_removed": true,
      "level": "medium",
      "metadata_by": "llm",
      "origin": "playbook",
      "rule_id": "ef0fb690-d875-5145-8b4f-afc8731c1f37",
      "technique": "T1110",
      "title": "Repeated Failed SSH Logins Against DEMO-SSH",
      "validation": {
        "cited_buckets": 1,
        "matching_buckets": 1,
        "ok": true,
        "other_buckets": []
      }
    },
    {
      "es_query": {
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
      "file": "actions/detections/T1078-b-203.0.113.99.yml",
      "from_step": "T1078-b-203.0.113.99",
      "host_scope_removed": true,
      "level": "critical",
      "metadata_by": "llm",
      "origin": "playbook",
      "rule_id": "0c3a8fcb-6227-5ac8-9f9f-97da3c101121",
      "technique": "T1078",
      "title": "Successful SSH Login from Brute-Forcing Source 203.0.113.99",
      "validation": {
        "cited_events": 1,
        "ok": true,
        "other_hits": 0,
        "total_hits": 1
      }
    },
    {
      "es_query": {
        "fields": [
          "@timestamp",
          "destination.port",
          "event.action",
          "event.outcome",
          "event.type",
          "host.name",
          "message",
          "process.name",
          "source.ip",
          "source.port",
          "user.name"
        ],
        "filters": [
          {
            "field": "event.dataset",
            "op": "eq",
            "value": "linux.auth"
          },
          {
            "field": "source.ip",
            "op": "eq",
            "value": "203.0.113.99"
          }
        ],
        "index": "security-events-c2test*",
        "size": 60,
        "time_from": "2026-10-25T00:10:00Z",
        "time_to": "2026-10-25T01:00:00Z"
      },
      "file": "actions/detections/AG-01.yml",
      "from_step": "AG-01",
      "host_scope_removed": true,
      "level": "high",
      "metadata_by": "llm",
      "origin": "llm",
      "rule_id": "bc50f9aa-3b5d-5636-9a65-670547527599",
      "technique": "T1078",
      "title": "Authentication Timeline for 203.0.113.99 on DEMO-SSH",
      "validation": {
        "cited_events": 31,
        "ok": true,
        "other_hits": 0,
        "total_hits": 31
      }
    }
  ],
  "notes": [],
  "response": [
    {
      "action": "block_ip",
      "claim_ids": [
        "C-001",
        "C-002"
      ],
      "reason": "The external source produced 30 failed SSH logins and then successfully authenticated to DEMO-SSH, so blocking it prevents further access attempts from this IP.",
      "status": "proposed: requires analyst approval",
      "target": "203.0.113.99"
    },
    {
      "action": "disable_account",
      "claim_ids": [
        "C-002",
        "C-003",
        "C-004"
      ],
      "reason": "The demo account was successfully accessed by the brute-forcing source and continued authentication activity followed, so the account should be disabled pending investigation.",
      "status": "proposed: requires analyst approval",
      "target": "demo"
    },
    {
      "action": "isolate_host",
      "claim_ids": [
        "C-002",
        "C-004"
      ],
      "reason": "DEMO-SSH had a successful SSH login from the brute-forcing external IP, so isolating the host limits potential lateral movement or post-compromise activity.",
      "status": "proposed: requires analyst approval",
      "target": "DEMO-SSH"
    },
    {
      "action": "reset_credentials",
      "claim_ids": [
        "C-002",
        "C-004"
      ],
      "reason": "The demo account's credentials were used in a successful login from the suspicious source, so credentials should be reset after containment.",
      "status": "proposed: requires analyst approval",
      "target": "demo"
    },
    {
      "action": "collect_forensics",
      "claim_ids": [
        "C-002",
        "C-003",
        "C-004"
      ],
      "reason": "Preserve authentication logs, host artifacts, and session evidence from DEMO-SSH to determine post-login actions and scope of compromise.",
      "status": "proposed: requires analyst approval",
      "target": "DEMO-SSH"
    }
  ]
}
```
**Run B**
```json
{
  "detections": [
    {
      "es_query": {
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
        "size": 20,
        "time_from": "2026-10-25T00:00:00Z",
        "time_to": "2026-10-25T01:00:00Z"
      },
      "file": "actions/detections/T1110-a.yml",
      "from_step": "T1110-a",
      "host_scope_removed": true,
      "level": "high",
      "metadata_by": "llm",
      "origin": "playbook",
      "rule_id": "ef0fb690-d875-5145-8b4f-afc8731c1f37",
      "technique": "T1110",
      "title": "Multiple Failed SSH Logins from Single Source on DEMO-SSH",
      "validation": {
        "cited_buckets": 1,
        "matching_buckets": 1,
        "ok": true,
        "other_buckets": []
      }
    },
    {
      "es_query": {
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
      "file": "actions/detections/T1078-b-203.0.113.99.yml",
      "from_step": "T1078-b-203.0.113.99",
      "host_scope_removed": true,
      "level": "critical",
      "metadata_by": "llm",
      "origin": "playbook",
      "rule_id": "0c3a8fcb-6227-5ac8-9f9f-97da3c101121",
      "technique": "T1078",
      "title": "Successful SSH Login from Brute-Forcing Source 203.0.113.99",
      "validation": {
        "cited_events": 1,
        "ok": true,
        "other_hits": 0,
        "total_hits": 1
      }
    },
    {
      "es_query": {
        "fields": [
          "@timestamp",
          "event.action",
          "event.original",
          "event.outcome",
          "host.name",
          "source.ip",
          "source.port",
          "user.name"
        ],
        "filters": [
          {
            "field": "event.dataset",
            "op": "eq",
            "value": "linux.auth"
          },
          {
            "field": "event.outcome",
            "op": "eq",
            "value": "success"
          }
        ],
        "index": "security-events-c2test*",
        "size": 100,
        "time_from": "2026-09-24T01:00:00Z",
        "time_to": "2026-10-25T01:00:00Z"
      },
      "file": "actions/detections/AG-01.yml",
      "from_step": "AG-01",
      "host_scope_removed": true,
      "level": "low",
      "metadata_by": "llm",
      "origin": "llm",
      "rule_id": "73c8667f-16b8-5877-ac2e-42ed3de26f70",
      "technique": "T1078",
      "title": "All Successful SSH Logins on DEMO-SSH for Basline Comparison",
      "validation": {
        "cited_events": 1,
        "ok": true,
        "other_hits": 1,
        "total_hits": 2
      }
    }
  ],
  "notes": [],
  "response": [
    {
      "action": "block_ip",
      "claim_ids": [
        "C-001",
        "C-002"
      ],
      "reason": "203.0.113.99 produced 30 failed SSH logins and then successfully authenticated to DEMO-SSH, indicating a brute-force compromise.",
      "status": "proposed: requires analyst approval",
      "target": "203.0.113.99"
    },
    {
      "action": "reset_credentials",
      "claim_ids": [
        "C-002",
        "C-003"
      ],
      "reason": "The demo account successfully logged in from the brute-forcing source 203.0.113.99 and should be treated as compromised.",
      "status": "proposed: requires analyst approval",
      "target": "demo"
    },
    {
      "action": "disable_account",
      "claim_ids": [
        "C-002",
        "C-003"
      ],
      "reason": "Disable the demo account pending investigation to prevent further unauthorized access from the successful brute-force login.",
      "status": "proposed: requires analyst approval",
      "target": "demo"
    },
    {
      "action": "isolate_host",
      "claim_ids": [
        "C-002",
        "C-003"
      ],
      "reason": "DEMO-SSH accepted a successful SSH login from 203.0.113.99 after failed brute-force attempts, so the host may be compromised.",
      "status": "proposed: requires analyst approval",
      "target": "DEMO-SSH"
    },
    {
      "action": "collect_forensics",
      "claim_ids": [
        "C-002",
        "C-003"
      ],
      "reason": "Preserve authentication logs and host artifacts from DEMO-SSH to determine post-login activity associated with the 203.0.113.99/demo session.",
      "status": "proposed: requires analyst approval",
      "target": "DEMO-SSH"
    }
  ]
}
```

### agent

**Run A**
```json
{
  "draft_mode": false,
  "enabled": true,
  "model": "openai:deepseek-flash@api.deepseek.com",
  "steps": [
    {
      "action": "search",
      "claims": [
        "C-003",
        "C-004"
      ],
      "n": 1,
      "params": {
        "fields": [
          "@timestamp",
          "destination.port",
          "event.action",
          "event.outcome",
          "event.type",
          "host.name",
          "message",
          "process.name",
          "source.ip",
          "source.port",
          "user.name"
        ],
        "filters": [
          {
            "field": "event.dataset",
            "op": "eq",
            "value": "linux.auth"
          },
          {
            "field": "host.name",
            "op": "eq",
            "value": "DEMO-SSH"
          },
          {
            "field": "source.ip",
            "op": "eq",
            "value": "203.0.113.99"
          }
        ],
        "size": 60,
        "time_from": "2026-10-25T00:10:00Z",
        "time_to": "2026-10-25T01:00:00Z"
      },
      "purpose": "All linux.auth events on DEMO-SSH from 203.0.113.99 at and after the first failed login, ordered in time, to see the fail-then-success sequence and any post-success authentication activity",
      "status": "ran",
      "step_id": "AG-01",
      "technique": "T1078",
      "thought": "A successful login from 203.0.113.99 already appears; the decisive follow-up is what that source did on DEMO-SSH after the success (continued auth attempts, different accounts, new sessions), which distinguishes a real account takeover from a benign one-off login.",
      "total": 31
    },
    {
      "action": "search",
      "claims": [],
      "n": 2,
      "params": {
        "fields": [
          "@timestamp",
          "host.name",
          "source.ip",
          "source.port",
          "user.name",
          "event.action",
          "event.outcome",
          "message"
        ],
        "filters": [
          {
            "field": "event.dataset",
            "op": "eq",
            "value": "linux.auth"
          },
          {
            "field": "host.name",
            "op": "eq",
            "value": "DEMO-SSH"
          },
          {
            "field": "event.outcome",
            "op": "eq",
            "value": "success"
          }
        ],
        "size": 20,
        "time_from": "2026-10-25T00:00:00Z",
        "time_to": "2026-10-25T01:00:00Z"
      },
      "purpose": "Successful SSH logins on DEMO-SSH in the hunt window: timestamp, source.ip, user.name and raw message, to confirm the success from 203.0.113.99 followed the failure burst and that no other source or a...",
      "status": "ran",
      "step_id": "AG-02",
      "technique": "T1078",
      "thought": "The findings already establish 30 failures from 203.0.113.99 followed by a success as demo on DEMO-SSH; one focused search on the successful login event itself (its message and timestamp) pins the fail-then-success ordering and confirms no other source/account succeeded, closing T1078.",
      "total": 1
    }
  ],
  "stopped_because": "turn limit (2) reached"
}
```
**Run B**
```json
{
  "draft_mode": false,
  "enabled": true,
  "model": "openai:deepseek-flash@api.deepseek.com",
  "steps": [
    {
      "action": "search",
      "claims": [
        "C-003"
      ],
      "n": 1,
      "params": {
        "fields": [
          "@timestamp",
          "event.action",
          "event.original",
          "event.outcome",
          "host.name",
          "source.ip",
          "source.port",
          "user.name"
        ],
        "filters": [
          {
            "field": "event.dataset",
            "op": "eq",
            "value": "linux.auth"
          },
          {
            "field": "host.name",
            "op": "eq",
            "value": "DEMO-SSH"
          },
          {
            "field": "event.outcome",
            "op": "eq",
            "value": "success"
          }
        ],
        "size": 100,
        "time_from": "2026-09-24T01:00:00Z",
        "time_to": "2026-10-25T01:00:00Z"
      },
      "purpose": "All successful SSH logins on DEMO-SSH to see whether the 203.0.113.99/demo success is unique or matches a normal baseline",
      "status": "ran",
      "step_id": "AG-01",
      "technique": "T1078",
      "thought": "C-002 already claims a success from 203.0.113.99; to judge whether it is anomalous (valid-account abuse) rather than normal admin activity, I need to enumerate every successful SSH login on DEMO-SSH and compare sources/users.",
      "total": 1
    },
    {
      "action": "check_ioc",
      "claims": [],
      "n": 2,
      "params": "203.0.113.99",
      "purpose": "Check reputation of the external brute-force source 203.0.113.99",
      "status": "ran",
      "step_id": "AG-02",
      "technique": "T1110",
      "thought": "The failed-then-successful pattern from 203.0.113.99 is already established by the playbook and confirmed as the only success on DEMO-SSH; the remaining gap is external threat-intel corroboration of the source IP, which would confirm the brute-force attribution (T1110) rather than refute it.",
      "total": 0
    }
  ],
  "stopped_because": "turn limit (2) reached"
}
```

### dynamic_steps

**Run A**
```json
[
  {
    "analysis": {},
    "claim_template": "",
    "must_have": false,
    "params": {
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
    "purpose": "Events behind aggregate bucket 203.0.113.99",
    "role": "context",
    "step_id": "T1110-a-dd-203.0.113.99",
    "technique": "T1110",
    "tool": "search"
  },
  {
    "analysis": {
      "sample_ok": true
    },
    "claim_template": "",
    "must_have": false,
    "params": {
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
    "purpose": "First failed SSH login from 203.0.113.99",
    "role": "context",
    "step_id": "T1078-first-203.0.113.99",
    "technique": "T1078",
    "tool": "search"
  },
  {
    "analysis": {
      "group_by": [
        "source.ip",
        "user.name",
        "host.name"
      ]
    },
    "claim_template": "Source {source.ip} logged in successfully as {user.name} on {host.name} after its failed SSH logins began",
    "must_have": true,
    "params": {
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
    "purpose": "Successful SSH logins from 203.0.113.99 after its first failed login (2026-10-25T00:10:00.000Z)",
    "role": "indicator",
    "step_id": "T1078-b-203.0.113.99",
    "technique": "T1078",
    "tool": "search"
  },
  {
    "analysis": {
      "group_by": [
        "user.name",
        "event.outcome",
        "source.ip",
        "host.name"
      ],
      "min_count": 1
    },
    "claim_template": "Source {source.ip} kept authenticating against DEMO-SSH with user {user.name} after the successful login, outcome {event.outcome}",
    "must_have": false,
    "params": {
      "fields": [
        "@timestamp",
        "destination.port",
        "event.action",
        "event.outcome",
        "event.type",
        "host.name",
        "message",
        "process.name",
        "source.ip",
        "source.port",
        "user.name"
      ],
      "filters": [
        {
          "field": "event.dataset",
          "op": "eq",
          "value": "linux.auth"
        },
        {
          "field": "host.name",
          "op": "eq",
          "value": "DEMO-SSH"
        },
        {
          "field": "source.ip",
          "op": "eq",
          "value": "203.0.113.99"
        }
      ],
      "index": "security-events-c2test*",
      "size": 60,
      "time_from": "2026-10-25T00:10:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "purpose": "All linux.auth events on DEMO-SSH from 203.0.113.99 at and after the first failed login, ordered in time, to see the fail-then-success sequence and any post-success authentication activity",
    "role": "context",
    "step_id": "AG-01",
    "technique": "T1078",
    "tool": "search"
  },
  {
    "analysis": {
      "claim_ignored": "claim: unknown field 'timestamp'; did you mean ['@timestamp']?"
    },
    "claim_template": "",
    "must_have": false,
    "params": {
      "fields": [
        "@timestamp",
        "host.name",
        "source.ip",
        "source.port",
        "user.name",
        "event.action",
        "event.outcome",
        "message"
      ],
      "filters": [
        {
          "field": "event.dataset",
          "op": "eq",
          "value": "linux.auth"
        },
        {
          "field": "host.name",
          "op": "eq",
          "value": "DEMO-SSH"
        },
        {
          "field": "event.outcome",
          "op": "eq",
          "value": "success"
        }
      ],
      "index": "security-events-c2test*",
      "size": 20,
      "time_from": "2026-10-25T00:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "purpose": "Successful SSH logins on DEMO-SSH in the hunt window: timestamp, source.ip, user.name and raw message, to confirm the success from 203.0.113.99 followed the failure burst and that no other source or a...",
    "role": "context",
    "step_id": "AG-02",
    "technique": "T1078",
    "tool": "search"
  },
  {
    "analysis": {},
    "claim_template": "",
    "must_have": false,
    "params": {
      "agg": "terms",
      "field": "host.name",
      "filters": [
        {
          "field": "event.dataset",
          "op": "eq",
          "value": "linux.auth"
        },
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
      "size": 100,
      "time_from": "2026-10-18T00:00:00Z",
      "time_to": "2026-10-25T00:00:00Z"
    },
    "purpose": "Check whether 203.0.113.99 produced failed SSH logins on prior days, which would support a recurring job with stale credentials rather than a one-off brute force.",
    "role": "benign_check",
    "step_id": "SK-01",
    "technique": "T1110",
    "tool": "aggregate"
  },
  {
    "analysis": {},
    "claim_template": "",
    "must_have": false,
    "params": {
      "agg": "terms",
      "field": "destination.port",
      "filters": [
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
    "purpose": "See whether the source contacted multiple destination ports in the hunt window, which is more consistent with a multi-service scanner than SSH-only brute force.",
    "role": "benign_check",
    "step_id": "SK-02",
    "technique": "T1110",
    "tool": "aggregate"
  },
  {
    "analysis": {},
    "claim_template": "",
    "must_have": false,
    "params": {
      "filters": [
        {
          "field": "event.dataset",
          "op": "eq",
          "value": "linux.auth"
        },
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
      "time_from": "2026-10-18T00:00:00Z",
      "time_to": "2026-10-25T00:00:00Z"
    },
    "purpose": "Check for successful SSH logins by demo from 203.0.113.99 on prior days, which would show the successful login is routine rather than a post-brute-force compromise.",
    "role": "benign_check",
    "step_id": "SK-03",
    "technique": "T1078",
    "tool": "count"
  },
  {
    "analysis": {},
    "claim_template": "",
    "must_have": false,
    "params": {
      "agg": "date_histogram",
      "field": "@timestamp",
      "filters": [
        {
          "field": "event.dataset",
          "op": "eq",
          "value": "linux.auth"
        },
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
      "interval": "1d",
      "size": 100,
      "time_from": "2026-10-18T00:00:00Z",
      "time_to": "2026-10-25T00:00:00Z"
    },
    "purpose": "Check whether successful demo logins from 203.0.113.99 recur across multiple prior days, which would support a scheduled automation job.",
    "role": "benign_check",
    "step_id": "SK-04",
    "technique": "T1078",
    "tool": "aggregate"
  }
]
```
**Run B**
```json
[
  {
    "analysis": {},
    "claim_template": "",
    "must_have": false,
    "params": {
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
    "purpose": "Events behind aggregate bucket 203.0.113.99",
    "role": "context",
    "step_id": "T1110-a-dd-203.0.113.99",
    "technique": "T1110",
    "tool": "search"
  },
  {
    "analysis": {
      "sample_ok": true
    },
    "claim_template": "",
    "must_have": false,
    "params": {
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
    "purpose": "First failed SSH login from 203.0.113.99",
    "role": "context",
    "step_id": "T1078-first-203.0.113.99",
    "technique": "T1078",
    "tool": "search"
  },
  {
    "analysis": {
      "group_by": [
        "source.ip",
        "user.name",
        "host.name"
      ]
    },
    "claim_template": "Source {source.ip} logged in successfully as {user.name} on {host.name} after its failed SSH logins began",
    "must_have": true,
    "params": {
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
    "purpose": "Successful SSH logins from 203.0.113.99 after its first failed login (2026-10-25T00:10:00.000Z)",
    "role": "indicator",
    "step_id": "T1078-b-203.0.113.99",
    "technique": "T1078",
    "tool": "search"
  },
  {
    "analysis": {
      "group_by": [
        "source.ip",
        "user.name",
        "host.name"
      ],
      "min_count": 1
    },
    "claim_template": "Successful SSH login as {user.name} from {source.ip}",
    "must_have": false,
    "params": {
      "fields": [
        "@timestamp",
        "event.action",
        "event.original",
        "event.outcome",
        "host.name",
        "source.ip",
        "source.port",
        "user.name"
      ],
      "filters": [
        {
          "field": "event.dataset",
          "op": "eq",
          "value": "linux.auth"
        },
        {
          "field": "host.name",
          "op": "eq",
          "value": "DEMO-SSH"
        },
        {
          "field": "event.outcome",
          "op": "eq",
          "value": "success"
        }
      ],
      "index": "security-events-c2test*",
      "size": 100,
      "time_from": "2026-09-24T01:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "purpose": "All successful SSH logins on DEMO-SSH to see whether the 203.0.113.99/demo success is unique or matches a normal baseline",
    "role": "context",
    "step_id": "AG-01",
    "technique": "T1078",
    "tool": "search"
  },
  {
    "analysis": {},
    "claim_template": "",
    "must_have": false,
    "params": {
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
      "time_from": "2026-10-24T00:00:00Z",
      "time_to": "2026-10-25T00:00:00Z"
    },
    "purpose": "Count failed SSH logins from 203.0.113.99 during the previous 24h (outside the hunt window) to see whether the same burst repeats on a schedule",
    "role": "benign_check",
    "step_id": "SK-01",
    "technique": "T1110",
    "tool": "count"
  },
  {
    "analysis": {},
    "claim_template": "",
    "must_have": false,
    "params": {
      "agg": "cardinality",
      "field": "host.name",
      "filters": [
        {
          "field": "source.ip",
          "op": "eq",
          "value": "203.0.113.99"
        }
      ],
      "index": "security-events-c2test*",
      "size": 100,
      "time_from": "2026-10-24T00:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "purpose": "Count distinct host.name values touched by 203.0.113.99 across all datasets in the preceding 24h; many hosts indicates a scanner sweep",
    "role": "benign_check",
    "step_id": "SK-02",
    "technique": "T1110",
    "tool": "aggregate"
  },
  {
    "analysis": {},
    "claim_template": "",
    "must_have": false,
    "params": {
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
      "time_from": "2026-10-24T00:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "purpose": "List the source IPs that successfully logged in as 'demo' over the previous day; multiple distinct IPs (including internal ranges) indicate normal multi-location use of a shared account",
    "role": "benign_check",
    "step_id": "SK-03",
    "technique": "T1078",
    "tool": "aggregate"
  },
  {
    "analysis": {},
    "claim_template": "",
    "must_have": false,
    "params": {
      "agg": "cardinality",
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
          "value": "success"
        }
      ],
      "index": "security-events-c2test*",
      "size": 100,
      "time_from": "2026-10-24T00:00:00Z",
      "time_to": "2026-10-25T01:00:00Z"
    },
    "purpose": "Count distinct user.name values that successfully authenticate from 203.0.113.99 over the previous day; many users means the IP is a shared gateway rather than an attacker host",
    "role": "benign_check",
    "step_id": "SK-04",
    "technique": "T1078",
    "tool": "aggregate"
  }
]
```

### intake

**Run A**
```json
{
  "assumptions": [
    "'external IP' is not a named entity, so no specific IP was recorded.",
    "SSH brute force mapped to T1110 and subsequent successful login to T1078; no SSH-specific catalogue technique exists.",
    "'on 2026-10-25' resolved to the full UTC day."
  ],
  "dropped": [],
  "source": "llm",
  "users": [],
  "window": {
    "basis": "date written in the hypothesis",
    "effective": {
      "from": "2026-10-25T00:00:00Z",
      "to": "2026-10-25T01:00:00Z"
    },
    "requested": {
      "from": "2026-10-25T00:00:00Z",
      "to": "2026-10-26T00:00:00Z"
    }
  }
}
```
**Run B**
```json
{
  "assumptions": [
    "The stated date 2026-10-25 was expanded to the full UTC day.",
    "No specific external IP or username is named, so those entity lists stay empty; the successful-login source should be derived from the failed-login burst during the hunt.",
    "The brute-force and subsequent successful SSH login are assumed to target the same host, DEMO-SSH."
  ],
  "dropped": [],
  "source": "llm",
  "users": [],
  "window": {
    "basis": "date written in the hypothesis",
    "effective": {
      "from": "2026-10-25T00:00:00Z",
      "to": "2026-10-25T01:00:00Z"
    },
    "requested": {
      "from": "2026-10-25T00:00:00Z",
      "to": "2026-10-26T00:00:00Z"
    }
  }
}
```

### manifest

**Run A**
```json
{
  "backend": "llm:openai:deepseek-flash@api.deepseek.com",
  "code_hash": "77d45cd02dffc406",
  "controls": {
    "act": true,
    "agent_loop": true,
    "canonical_order": true,
    "canonical_params": true,
    "complete_results": true,
    "coverage_enforcement": true,
    "deterministic_sampling": true,
    "skeptic": true
  },
  "ignored_tools": [
    "es.get_event",
    "es.save_finding",
    "es.get_audit_log"
  ],
  "index": "security-events-c2test*",
  "llm": {
    "calls": 6,
    "max_calls": 8,
    "tokens_in": 13657,
    "tokens_out": 9475,
    "trace": "runs/attack/llm.jsonl"
  },
  "mcp_servers": {
    "analytics": "python -m analytics_server.server",
    "es": "/tmp/smtd-e2e-20261026-venv/bin/python -m es_mcp_server.server"
  },
  "perturb_seed": null,
  "planner": "llm",
  "python": "3.11.16",
  "temperature": 0.0,
  "tool_calls": 25
}
```
**Run B**
```json
{
  "backend": "llm:openai:deepseek-flash@api.deepseek.com",
  "code_hash": "77d45cd02dffc406",
  "controls": {
    "act": true,
    "agent_loop": true,
    "canonical_order": true,
    "canonical_params": true,
    "complete_results": true,
    "coverage_enforcement": true,
    "deterministic_sampling": true,
    "skeptic": true
  },
  "ignored_tools": [
    "es.get_event",
    "es.save_finding",
    "es.get_audit_log"
  ],
  "index": "security-events-c2test*",
  "llm": {
    "calls": 6,
    "max_calls": 8,
    "tokens_in": 8928,
    "tokens_out": 8084,
    "trace": "runs/attack-repeat/llm.jsonl"
  },
  "mcp_servers": {
    "analytics": "python -m analytics_server.server",
    "es": "/tmp/smtd-e2e-20261026-venv/bin/python -m es_mcp_server.server"
  },
  "perturb_seed": null,
  "planner": "llm",
  "python": "3.11.16",
  "temperature": 0.0,
  "tool_calls": 25
}
```

### self_check

**Run A**
```json
{
  "claims": 4,
  "failed": [],
  "self_checked": 4
}
```
**Run B**
```json
{
  "claims": 3,
  "failed": [],
  "self_checked": 3
}
```

### skeptic

**Run A**
```json
{
  "alternatives": [
    {
      "benign_if": ">0",
      "claim_id": "C-001",
      "explanation": "A recurring scheduled job or monitoring agent at 203.0.113.99 retries an outdated SSH credential against DEMO-SSH, producing repeated failures.",
      "measure": "buckets",
      "measured": 0,
      "outcome": "ruled_out",
      "step_id": "SK-01",
      "total": 0
    },
    {
      "benign_if": ">=2",
      "claim_id": "C-001",
      "explanation": "203.0.113.99 is an authorized scanner or monitoring service that probes multiple services, so the SSH failures are expected scanner noise.",
      "measure": "buckets",
      "measured": 0,
      "outcome": "ruled_out",
      "step_id": "SK-02",
      "total": 31
    },
    {
      "benign_if": ">0",
      "claim_id": "C-002",
      "explanation": "User demo is a legitimate remote administrator who habitually logs in from 203.0.113.99 and simply mistyped the password before succeeding.",
      "measure": "hits",
      "measured": 0,
      "outcome": "ruled_out",
      "step_id": "SK-03",
      "total": 0
    },
    {
      "benign_if": ">=2",
      "claim_id": "C-002",
      "explanation": "demo is an automation account used by a scheduled deployment or backup job from 203.0.113.99, so the successful login is routine non-interactive activity.",
      "measure": "hits",
      "measured": 0,
      "outcome": "ruled_out",
      "step_id": "SK-04",
      "total": 0
    }
  ],
  "enabled": true,
  "model": "openai:deepseek-flash@api.deepseek.com"
}
```
**Run B**
```json
{
  "alternatives": [
    {
      "benign_if": ">=20",
      "claim_id": "C-001",
      "explanation": "The 30 failures are a recurring automated job (backup/sync/monitoring agent on an external cloud host) retrying stale SSH credentials on its normal schedule, not a human brute force.",
      "measure": "hits",
      "measured": 0,
      "outcome": "ruled_out",
      "step_id": "SK-01",
      "total": 0
    },
    {
      "benign_if": ">=3",
      "claim_id": "C-001",
      "explanation": "203.0.113.99 is an authorised scanning host (vulnerability/compliance scanner or pen-test box) that sweeps many hosts, so a burst of failures against DEMO-SSH is a scan artefact rather than targeted credential guessing.",
      "measure": "distinct values",
      "measured": 1,
      "outcome": "ruled_out",
      "step_id": "SK-02",
      "total": 31
    },
    {
      "benign_if": ">=3",
      "claim_id": "C-002",
      "explanation": "The 'demo' account is a shared test/lab account that normally authenticates successfully from several different source IPs, so one more success from an external address is routine use, not post-brute-force access.",
      "measure": "buckets",
      "measured": 2,
      "outcome": "ruled_out",
      "step_id": "SK-03",
      "total": 2
    },
    {
      "benign_if": ">=3",
      "claim_id": "C-002",
      "explanation": "203.0.113.99 is a legitimate shared egress/VPN/vendor-support gateway through which many real users authenticate, so a success as 'demo' from it is expected traffic.",
      "outcome": "not_discriminating",
      "reason": "the test only re-measures the finding's own evidence, so it cannot tell the benign story from the attack",
      "step_id": "SK-04",
      "total": 1
    }
  ],
  "enabled": true,
  "model": "openai:deepseek-flash@api.deepseek.com"
}
```

### step_results

**Run A**
```json
{
  "AG-01": {
    "complete": true,
    "status": "ok",
    "tool": "search",
    "total": 31
  },
  "AG-02": {
    "complete": true,
    "status": "ok",
    "tool": "search",
    "total": 1
  },
  "SK-01": {
    "status": "ok",
    "tool": "aggregate",
    "total": 0
  },
  "SK-02": {
    "status": "ok",
    "tool": "aggregate",
    "total": 31
  },
  "SK-03": {
    "status": "ok",
    "tool": "count",
    "total": 0
  },
  "SK-04": {
    "status": "ok",
    "tool": "aggregate",
    "total": 0
  },
  "T1078-a": {
    "status": "ok",
    "tool": "aggregate",
    "total": 30
  },
  "T1078-b-203.0.113.99": {
    "complete": true,
    "status": "ok",
    "tool": "search",
    "total": 1
  },
  "T1078-first-203.0.113.99": {
    "complete": false,
    "status": "ok",
    "tool": "search",
    "total": 30
  },
  "T1110-a": {
    "status": "ok",
    "tool": "aggregate",
    "total": 30
  },
  "T1110-a-dd-203.0.113.99": {
    "complete": true,
    "status": "ok",
    "tool": "search",
    "total": 30
  }
}
```
**Run B**
```json
{
  "AG-01": {
    "complete": true,
    "status": "ok",
    "tool": "search",
    "total": 1
  },
  "SK-01": {
    "status": "ok",
    "tool": "count",
    "total": 0
  },
  "SK-02": {
    "status": "ok",
    "tool": "aggregate",
    "total": 31
  },
  "SK-03": {
    "status": "ok",
    "tool": "aggregate",
    "total": 2
  },
  "SK-04": {
    "status": "ok",
    "tool": "aggregate",
    "total": 1
  },
  "T1078-a": {
    "status": "ok",
    "tool": "aggregate",
    "total": 30
  },
  "T1078-b-203.0.113.99": {
    "complete": true,
    "status": "ok",
    "tool": "search",
    "total": 1
  },
  "T1078-first-203.0.113.99": {
    "complete": false,
    "status": "ok",
    "tool": "search",
    "total": 30
  },
  "T1110-a": {
    "status": "ok",
    "tool": "aggregate",
    "total": 30
  },
  "T1110-a-dd-203.0.113.99": {
    "complete": true,
    "status": "ok",
    "tool": "search",
    "total": 30
  }
}
```

### techniques

**Run A**
```json
[
  {
    "accepted_claims": 1,
    "any_signal": true,
    "covered": true,
    "gaps": [],
    "leads": [],
    "min_support": 1,
    "name": "Brute Force",
    "required": true,
    "sources": [
      "auth"
    ],
    "supported": true,
    "supporting_steps": [
      "T1110-a"
    ],
    "technique": "T1110",
    "usable_sources": [
      "auth"
    ]
  },
  {
    "accepted_claims": 1,
    "any_signal": true,
    "covered": true,
    "gaps": [],
    "leads": [
      "C-003",
      "C-004"
    ],
    "min_support": 1,
    "name": "Valid Accounts",
    "required": true,
    "sources": [
      "auth"
    ],
    "supported": true,
    "supporting_steps": [
      "T1078-b-203.0.113.99"
    ],
    "technique": "T1078",
    "usable_sources": [
      "auth"
    ]
  }
]
```
**Run B**
```json
[
  {
    "accepted_claims": 1,
    "any_signal": true,
    "covered": true,
    "gaps": [],
    "leads": [],
    "min_support": 1,
    "name": "Brute Force",
    "required": true,
    "sources": [
      "auth"
    ],
    "supported": true,
    "supporting_steps": [
      "T1110-a"
    ],
    "technique": "T1110",
    "usable_sources": [
      "auth"
    ]
  },
  {
    "accepted_claims": 1,
    "any_signal": true,
    "covered": true,
    "gaps": [],
    "leads": [
      "C-003"
    ],
    "min_support": 1,
    "name": "Valid Accounts",
    "required": true,
    "sources": [
      "auth"
    ],
    "supported": true,
    "supporting_steps": [
      "T1078-b-203.0.113.99"
    ],
    "technique": "T1078",
    "usable_sources": [
      "auth"
    ]
  }
]
```


## Notes

Only execution IDs (run_id, call_id, query_id) and manifest execution duration, phase timings and audit-file paths are ignored. Event timestamps, claim facts, evidence links, evidence contents, and query requests/values are preserved.
This compares saved C2 outputs; it does not rerun hunts or establish correctness.
