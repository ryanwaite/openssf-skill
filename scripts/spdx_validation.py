"""Optional offline SPDX 2.3 schema validation, separate from inventory quality."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys


SCHEMA = Path(__file__).resolve().parent.parent / "references/sbom/spdx-2.3.schema.json"
SCHEMA_SHA256 = "239208b7ac287b3cf5d9a9af23f9d69863971102a5e1587a27a398b43490b89b"
SCHEMA_SOURCE = ("https://github.com/spdx/spdx-spec/blob/"
                 "aadf3b0b8dbbabdb4d880b0fc714255fea436ff7/schemas/spdx-schema.json")


def validate_spdx(document):
    """Validate bounded JSON with the pinned schema and optional isolated library."""
    try:
        content = json.dumps(document, allow_nan=False).encode("utf-8")
        if len(content) > 8 * 1024 * 1024:
            raise ValueError("SPDX schema input exceeds 8 MiB")
        if hashlib.sha256(SCHEMA.read_bytes()).hexdigest() != SCHEMA_SHA256:
            return {"status": "unknown", "source": SCHEMA_SOURCE,
                    "reason": "Bundled SPDX schema does not match the pinned release"}
    except (OSError, ValueError, TypeError, RecursionError):
        return {"status": "error", "source": SCHEMA_SOURCE,
                "reason": "SPDX schema input or pinned local schema is unavailable"}
    program = """
import json, sys
from importlib.metadata import PackageNotFoundError, version
try:
    if version("jsonschema") != "4.25.1":
        raise PackageNotFoundError
    from jsonschema import Draft7Validator
    from jsonschema.exceptions import ValidationError, SchemaError
except (ImportError, PackageNotFoundError):
    sys.exit(3)
try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        schema = json.load(stream)
    Draft7Validator.check_schema(schema)
    Draft7Validator(schema).validate(json.load(sys.stdin))
except ValidationError:
    sys.exit(4)
except (SchemaError, ValueError, OSError, RecursionError):
    sys.exit(5)
"""
    try:
        result = subprocess.run(
            [sys.executable, "-I", "-c", program, str(SCHEMA)],
            input=content, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=15, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "unknown", "source": SCHEMA_SOURCE,
                "reason": "Optional schema validator unavailable or timed out"}
    if result.returncode == 0:
        return {"status": "valid", "source": SCHEMA_SOURCE,
                "reason": "Official SPDX 2.3 JSON schema accepted the structure; truth/completeness unverified"}
    if result.returncode == 4:
        return {"status": "invalid", "source": SCHEMA_SOURCE,
                "reason": "Document does not satisfy the official SPDX 2.3 JSON schema"}
    return {"status": "unknown", "source": SCHEMA_SOURCE,
            "reason": "Optional jsonschema==4.25.1 required; base inventory remains available"}
