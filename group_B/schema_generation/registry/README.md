# B2 schema registry

This directory is the default location for validated B2 schema entries. The
runtime layout is:

```text
registry/
  index.json
  schemas/<schema_id>/v<version>.json
```

Each entry stores the declarative `SchemaSpec`, the compiled Elasticsearch
ingest pipeline, the pipeline ID, the validation report and provenance. The
index maps a structural source signature hash to the latest registered entry
for that signature.

Registration requires the original samples as `samples=...`. Before writing,
the registry recomputes the signature, recompiles and compares the pipeline,
and freshly validates it. Stored reports and sample hashes describe that run;
an imported `accepted: true` flag is insufficient. Live-mode reports require
an Elasticsearch client for another `_simulate` call.

Entry and index writes each use a temporary file followed by `os.replace`.
They are not a multi-file transaction. The registry and CLI assume one writer;
callers must serialize concurrent writes. Existing entries are not migrated
automatically; regenerate pipelines that use the old singular Grok property.
