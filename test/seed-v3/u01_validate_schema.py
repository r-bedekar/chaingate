"""U-01 A9 interim validator: full JSON Schema (draft 2020-12) validation with Python jsonschema.

STAND-IN for the approved ajv devDependency, which is not available offline on this host (npm cache
empty; no local copy). Usage:
    python3 u01_validate_schema.py <check-schema> <finding-schema> <valid-dir> <invalid-dir>
Every file in <valid-dir> must validate (and its `finding`, if any, against the finding schema);
every file in <invalid-dir> must NOT validate. Prints one JSON summary line; exit 0 only if all hold.
"""
import json, sys
from pathlib import Path
import jsonschema
from jsonschema import Draft202012Validator, RefResolver

check_schema = json.loads(Path(sys.argv[1]).read_text())
finding_schema = json.loads(Path(sys.argv[2]).read_text())
Draft202012Validator.check_schema(check_schema)
Draft202012Validator.check_schema(finding_schema)
store = {finding_schema["$id"]: finding_schema, check_schema["$id"]: check_schema}
resolver = RefResolver.from_schema(check_schema, store=store)
check_v = Draft202012Validator(check_schema, resolver=resolver)
finding_v = Draft202012Validator(finding_schema)

failures, summary = [], {"validator": f"python-jsonschema {jsonschema.__version__}", "valid_ok": 0,
                         "findings_ok": 0, "invalid_rejected": 0}
for f in sorted(Path(sys.argv[3]).glob("*.json")):
    rec = json.loads(f.read_text())
    errs = sorted(check_v.iter_errors(rec), key=lambda e: list(e.path))
    if errs:
        failures.append(f"{f.name}: {errs[0].message[:300]} at /{'/'.join(map(str, errs[0].path))}")
        continue
    summary["valid_ok"] += 1
    if "finding" in rec:
        ferrs = list(finding_v.iter_errors(rec["finding"]))
        if ferrs:
            failures.append(f"{f.name}: finding: {ferrs[0].message[:300]}")
        else:
            summary["findings_ok"] += 1
for f in sorted(Path(sys.argv[4]).glob("*.json")):
    rec = json.loads(f.read_text())
    if check_v.is_valid(rec):
        failures.append(f"{f.name}: ACCEPTED but must be rejected")
    else:
        summary["invalid_rejected"] += 1
summary["failures"] = failures
print(json.dumps(summary))
sys.exit(1 if failures else 0)
