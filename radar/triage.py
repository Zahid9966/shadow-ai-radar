"""Alert triage summaries. Uses Claude when ANTHROPIC_API_KEY is set (opt-in; only already-redacted evidence leaves
the machine), otherwise a deterministic offline fallback so the tool never depends on an external service."""
import json
import os
import urllib.request

PLAYBOOK = {
    "SECRET_LEAK": "Treat the credential as compromised: rotate it, review its recent use in cloud audit logs, then coach the user.",
    "PII_LEAK": "Open a privacy incident, identify the data subjects, and ask legal whether notification is required.",
    "EXFIL_VOLUME": "Confirm with the user's manager what was uploaded and why; check for a bulk export just before the upload.",
    "OFF_HOURS": "Ask the user or manager if the late-night activity was expected, then review what was sent and to which service.",
    "SHADOW_ADOPTION": "Start a vendor risk review; decide approve/block and give people a sanctioned alternative.",
}


def offline(a):
    return (f"[{a['severity'].upper()}] {a['title']} (user: {a['user'] or 'multiple'}, {a['day']}). "
            f"Evidence: {a['evidence']}. Next step: {PLAYBOOK.get(a['kind'], a['action'])}")


def summarize(a, model="claude-sonnet-5-5", timeout=20):
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return offline(a), "offline"
    prompt = ("You are a security analyst assistant. In 3 sentences: what happened, how worried to be, and the first two "
              f"actions. Alert (evidence already redacted): {json.dumps({k: a[k] for k in ('kind','severity','title','evidence','count')})}")
    req = urllib.request.Request("https://api.anthropic.com/v1/messages", method="POST", headers={
        "x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
        data=json.dumps({"model": model, "max_tokens": 300, "messages": [{"role": "user", "content": prompt}]}).encode())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)["content"][0]["text"], "claude"
    except Exception as ex:  # network/auth/quota: degrade, never block the analyst
        return offline(a) + f" (AI summary unavailable: {type(ex).__name__})", "offline"
