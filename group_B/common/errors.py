"""Error types shared by Group B components.

Each error carries a stable machine-readable code and a process exit code so
the B2/B3 CLIs can report failures consistently.
"""

from __future__ import annotations

from typing import Any


class GroupBError(Exception):
    """Base class for expected Group B failures."""

    code = "GROUP_B_ERROR"
    exit_code = 1

    def __init__(self, message: str, **details: Any) -> None:
        super().__init__(message)
        self.message = message
        self.details = details

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": False,
            "error": {
                "code": self.code,
                "message": self.message,
                "details": self.details,
            },
        }


class RecognitionError(GroupBError):
    code = "RECOGNITION_FAILED"


class SchemaGenerationError(GroupBError):
    code = "SCHEMA_GENERATION_FAILED"


class SchemaValidationError(GroupBError):
    code = "SCHEMA_VALIDATION_FAILED"
    exit_code = 3


class RegistryError(GroupBError):
    code = "REGISTRY_ERROR"


class IngestionError(GroupBError):
    code = "INGESTION_FAILED"


class VerificationError(GroupBError):
    code = "VERIFICATION_FAILED"


class ConfigurationError(GroupBError):
    code = "CONFIGURATION_ERROR"
