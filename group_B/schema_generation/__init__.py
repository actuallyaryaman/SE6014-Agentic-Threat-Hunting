"""B2 — unknown-schema generation.

Batch 1 provides the declarative schema model, structural signatures, the
versioned registry, and signature-based reuse detection. Later batches add the
Elasticsearch pipeline compiler, validator, agent-driven generator, and CLI.
"""

from group_B.schema_generation.detect import DetectionResult, SchemaDetector
from group_B.schema_generation.models import (
    CsvParser,
    DissectParser,
    FieldSpec,
    FieldType,
    GrokParser,
    JsonParser,
    KvParser,
    Provenance,
    RegexParser,
    SchemaSpec,
    TimestampSpec,
    ValidationReport,
)
from group_B.schema_generation.registry import (
    RegistryEntry,
    RegistryIndex,
    SchemaRegistry,
    SignatureIndexEntry,
    default_registry_root,
)
from group_B.schema_generation.signature import (
    DEFAULT_MAX_SAMPLE_LINES,
    SIGNATURE_VERSION,
    SignatureKind,
    SourceSignature,
    build_signature,
)

__all__ = [
    "CsvParser",
    "DEFAULT_MAX_SAMPLE_LINES",
    "DetectionResult",
    "DissectParser",
    "FieldSpec",
    "FieldType",
    "GrokParser",
    "JsonParser",
    "KvParser",
    "Provenance",
    "RegexParser",
    "RegistryEntry",
    "RegistryIndex",
    "SIGNATURE_VERSION",
    "SchemaDetector",
    "SchemaRegistry",
    "SchemaSpec",
    "SignatureIndexEntry",
    "SignatureKind",
    "SourceSignature",
    "TimestampSpec",
    "ValidationReport",
    "build_signature",
    "default_registry_root",
]
