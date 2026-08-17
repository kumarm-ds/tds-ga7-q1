import os
import re
from flask import Flask, request, jsonify

app = Flask(__name__)

SHA_RE = re.compile(r"^[0-9a-f]{40}$")

def check_permissions(perms):
    expected = {"contents": "read", "packages": "write", "id-token": "none"}
    if perms != expected:
        return ["EXCESS_PERMISSION"]
    return []

def check_workflow_safety(payload):
    violations = []
    wf = payload["workflow"]
    if wf.get("trigger") == "pull_request_target":
        violations.append("UNSAFE_PR_TRIGGER")
    if not (wf.get("testsPassed") is True
            and wf.get("matrixComplete") is True
            and wf.get("failFast") is False):
        violations.append("TESTS_INCOMPLETE")
    return violations

def check_actions(actions):
    for a in actions:
        if a.get("owner") == "actions":
            continue
        ref = a.get("ref", "")
        if not SHA_RE.match(ref):
            return ["MUTABLE_ACTION"]
    return []

def check_image(image):
    violations = []
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")
    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")
    if image.get("secretMode") not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")
    if image.get("criticalVulnerabilities", 1) != 0:
        violations.append("CRITICAL_CVE")
    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")
    return violations

def check_production(payload):
    violations = []
    if payload.get("target") == "production":
        if not (payload.get("event") == "push"
                and payload.get("ref") == "refs/heads/main"):
            violations.append("INVALID_PRODUCTION_REF")
        if payload["workflow"].get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")
    return violations

@app.route("/release-gate", methods=["POST"])
def release_gate():
    payload = request.get_json(force=True)
    wf = payload["workflow"]

    violations = []
    violations += check_permissions(wf.get("permissions", {}))
    violations += check_workflow_safety(payload)
    violations += check_actions(wf.get("actions", []))
    violations += check_image(payload.get("image", {}))
    violations += check_production(payload)

    decision = "promote" if not violations else "block"
    return jsonify({"decision": decision, "violations": violations})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port)