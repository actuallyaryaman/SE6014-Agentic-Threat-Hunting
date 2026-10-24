# Windows JSON Pipeline (B1)

Elasticsearch ingest pipeline that parses Windows event logs in JSON (Sysmon and Security events, Mordor format) into the common normalized fields (see `shared/common-fields.md`).

Each log line is ingested as raw text in the `message` field. The pipeline parses the JSON, keeps the original line in `event.original`, and renames fields.

## How to use
1. Open Kibana > Dev Tools.
2. Run the `PUT` request below to create the pipeline.
3. Run the `POST` request to test it with a sample attack event.

## Create the pipeline
```
PUT _ingest/pipeline/windows-json
{
  "description": "Windows/Sysmon JSON events to common fields",
  "processors": [
    { "json": { "field": "message", "add_to_root": true } },
    { "set": { "field": "event.original", "copy_from": "message" } },
    { "remove": { "field": "message" } },
    { "rename": { "field": "host", "target_field": "observer.hostname", "ignore_missing": true } },
    { "rename": { "field": "EventID", "target_field": "event.code", "ignore_missing": true } },
    { "rename": { "field": "Hostname", "target_field": "host.name", "ignore_missing": true } },
    { "rename": { "field": "SourceIp", "target_field": "source.ip", "ignore_missing": true } },
    { "rename": { "field": "IpAddress", "target_field": "source.ip", "ignore_missing": true } },
    { "rename": { "field": "SourcePort", "target_field": "source.port", "ignore_missing": true } },
    { "rename": { "field": "IpPort", "target_field": "source.port", "ignore_missing": true } },
    { "rename": { "field": "DestinationIp", "target_field": "destination.ip", "ignore_missing": true } },
    { "rename": { "field": "DestinationPort", "target_field": "destination.port", "ignore_missing": true } },
    { "rename": { "field": "User", "target_field": "user.name", "ignore_missing": true } },
    { "rename": { "field": "SubjectUserName", "target_field": "user.name", "ignore_missing": true } },
    { "rename": { "field": "Image", "target_field": "process.executable", "ignore_missing": true } },
    { "rename": { "field": "ProcessId", "target_field": "process.pid", "ignore_missing": true } },
    { "convert": { "field": "event.code", "type": "string", "ignore_missing": true } },
    { "convert": { "field": "source.port", "type": "long", "ignore_missing": true } },
    { "convert": { "field": "destination.port", "type": "long", "ignore_missing": true } },
    { "convert": { "field": "process.pid", "type": "long", "ignore_missing": true } },
    { "set": { "field": "event.dataset", "copy_from": "Channel", "ignore_empty_value": true } }
  ]
}
```

## Test it (attack event: Security 5145, lsarpc pipe access)
```
POST _ingest/pipeline/windows-json/_simulate
{
  "docs": [
    {
      "_source": {
        "message": """{"@timestamp":"2020-10-22T18:33:36.923Z","OpcodeValue":0,"port":58121,"AccessReason":"-","Severity":"INFO","SubjectUserSid":"S-1-5-21-2323213074-4052461197-1785501644-1104","EventTime":"2020-10-22 14:33:27","SourceName":"Microsoft-Windows-Security-Auditing","ProviderGuid":"{54849625-5478-4994-A5BA-3E3B0328C30D}","Channel":"Security","SubjectUserName":"pgustavo","EventReceivedTime":"2020-10-22 14:33:30","ExecutionProcessID":4,"EventID":5145,"Category":"Detailed File Share","SubjectDomainName":"THESHIRE","SubjectLogonId":"0x2b7e3c0","ERROR_EVT_UNRESOLVED":true,"ObjectType":"File","SeverityValue":2,"Keywords":-9214364837600034816,"EventType":"AUDIT_SUCCESS","Version":0,"tags":["mordorDataset"],"ShareName":"\\\\*\\IPC$","SourceModuleName":"eventlog","SourceModuleType":"im_msvistalog","IpAddress":"172.18.39.5","host":"wec.internal.cloudapp.net","AccessList":"%%1538\r\n\t\t\t\t%%1541\r\n\t\t\t\t%%4416\r\n\t\t\t\t%%4417\r\n\t\t\t\t%%4418\r\n\t\t\t\t%%4419\r\n\t\t\t\t%%4420\r\n\t\t\t\t%%4423\r\n\t\t\t\t%%4424\r\n\t\t\t\t","RecordNumber":624080,"ThreadID":2748,"Task":12811,"IpPort":"64546","Hostname":"MORDORDC.theshire.local","AccessMask":"0x12019f","@version":"1","RelativeTargetName":"lsarpc","Opcode":"Info"}"""
      }
    }
  ]
}
```

## Expected result (tested)
| Field | Value |
|---|---|
| `event.code` | `"5145"` |
| `event.dataset` | `Security` |
| `host.name` | MORDORDC.theshire.local |
| `source.ip` | 172.18.39.5 |
| `source.port` | 64546 |
| `user.name` | pgustavo |
| `event.original` | the raw JSON line |

A Sysmon network event (Event ID 3) was also tested: `destination.ip`, `destination.port`, `process.executable` and `process.pid` are filled correctly.

## Notes
- The line's own `host` field is the log collector, so it is moved to `observer.hostname`. `host.name` is the actual computer.
- `@timestamp` is kept as it comes in the data (UTC, time the collector received the event).
- Fields not in the common list (for example `RelativeTargetName`, `ShareName`) stay as raw fields for now.
- Test data: OTRF Security-Datasets `empire_mimikatz_backupkeys_dcerpc_smb_lsarpc_2020-10-22143243.json`.
