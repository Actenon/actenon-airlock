"""Offline inventory comparison, never an acceptance allowlist generator."""

import hashlib
import inspect
import json
import re
import sys
from pathlib import Path

import openai
from openai.types.responses import Response

from actenon_airlock.responses_inference import _RESPONSE_FIELDS

root = Path(__file__).resolve().parent
reference = Path(sys.argv[1])
documented = set(re.findall(r"^  - `([a-z_]+):", reference.read_text(), re.M))
notes = json.loads((root / "matrix_notes.json").read_text())
fields = set(Response.model_fields) | _RESPONSE_FIELDS | documented
assert fields == set(notes), (fields - set(notes), set(notes) - fields)
assert openai.__version__ == "2.54.0"
live = {
    "presence_penalty": "V4.1 signed property-name hash; value unknown",
    "frequency_penalty": "V4.1 signed property-name hash; value unknown",
    "tool_usage": "V4.1 signed property-name hash; value unknown",
    "tools": "V4.2 response-tools rejection; nested offending names/values unknown",
    "image": "V4.3 signed public property identifier; value unknown",
}
rows = []
for field in sorted(fields):
    category, relevance, rule = notes[field]
    rows.append(
        {
            "field": field,
            "airlock": field in _RESPONSE_FIELDS,
            "sdk_2_54_0_declared": field in Response.model_fields,
            "current_reference": field in documented,
            "status": category,
            "relevance": relevance.split(","),
            "rule": rule,
            "live": live.get(field, "No field-specific signed diagnostic identification"),
            "sdk_annotation": str(Response.model_fields[field].annotation)
            if field in Response.model_fields
            else None,
        }
    )
result = {
    "schema": "actenon-airlock/response-compatibility-matrix/v1",
    "review_date": "2026-11-03",
    "sdk_version": openai.__version__,
    "sdk_response_sha256": hashlib.sha256(Path(inspect.getfile(Response)).read_bytes()).hexdigest(),
    "reference_url": "https://developers.openai.com/api/reference/resources/responses/methods/retrieve",
    "reference_markdown_sha256": hashlib.sha256(reference.read_bytes()).hexdigest(),
    "v4_limitation": "V4 only proved response-schema at event zero; conversation/moderation/prompt_cache_options were SDK candidates, not recovered live names.",
    "fields": rows,
}
(root / "compatibility-matrix.json").write_text(json.dumps(result, indent=2) + "\n")
lines = [
    "# Response compatibility matrix v1 — 2026-11-03",
    "",
    "This is an inventory and semantic review, not a permission generator. `accepted` means the existing inbound allowlist admits the property; it does **not** imply full value validation. Restricted and unsupported forms are explicit. The V4.4 repair expands only `image`. The table exposes inherited semantic gaps rather than silently tightening or broadening them.",
    "",
    "Source: [official retrieve reference](https://developers.openai.com/api/reference/resources/responses/methods/retrieve), exact installed OpenAI SDK 2.54.0, and Airlock validators. JSON records exact inventories, SDK annotations and source hashes. `output_text` is documented as SDK-only convenience. SDK declaration and current API documentation are distinct evidence.",
    "",
    "V4 has no recovered field-name set. V4.1 identifies presence_penalty, frequency_penalty and tool_usage by signed hashes. V4.2 identifies tools validation, not the nested offending properties. V4.3 identifies image, not its value. Other rows are not claimed as reconstructed live contents.",
    "",
    "| Field | Airlock / SDK / docs | Classification; relevance | Actual acceptance / limitation |",
    "|---|---|---|---|",
]
for row in rows:
    membership = " / ".join(
        "yes" if row[k] else "no" for k in ("airlock", "sdk_2_54_0_declared", "current_reference")
    )
    lines.append(
        f"| `{row['field']}` | {membership} | {row['status']}; {', '.join(row['relevance'])} | {row['rule']} |"
    )
lines.extend(
    [
        "",
        "Arbitrary additional fields remain unsupported (unknown/insufficiently documented). Fixed public names are diagnostic identifiers only. Inherited opaque echoes such as prompt, retention and service_tier deserve separate semantic review before expanding supported request features or treating their values as provider guarantees. Their admission never authorizes state, tool execution or a different price schedule.",
        "",
    ]
)
(root / "COMPATIBILITY_MATRIX.md").write_text("\n".join(lines))
