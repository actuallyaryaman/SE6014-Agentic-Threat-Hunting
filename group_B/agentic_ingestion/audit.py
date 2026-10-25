"""Append-only local run evidence, without raw logs or credentials."""

import fcntl
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path

from group_B.common.errors import IngestionError


class AuditError(IngestionError):
    code = "AUDIT_WRITE_FAILED"


class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)

    def write(self, event: dict):
        descriptor = directory = None
        try:
            # This is an explicit operator output path, not a source-selected path.
            self.path.parent.mkdir(parents=True, exist_ok=True)
            directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            descriptor = os.open(self.path.name, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                                 0o600, dir_fd=directory)
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise AuditError("audit destination must be a regular file")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            payload = dict(event, timestamp=datetime.now(timezone.utc).isoformat())
            data = (json.dumps(payload, sort_keys=True) + "\n").encode()
            with os.fdopen(descriptor, "ab", closefd=False) as stream:
                stream.write(data)
                stream.flush()
                os.fsync(descriptor)
        except (OSError, ValueError, TypeError) as error:
            raise AuditError("could not persist the run audit record") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if directory is not None:
                os.close(directory)
