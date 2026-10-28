"""AI service catalog + discovery heuristic for AI tools nobody has vetted yet."""
import re

# domain suffix -> (service name, policy status)
CATALOG = {
    "ai-gateway.corp.example.com": ("Corp AI Gateway", "sanctioned"),
    "copilot.microsoft.com": ("M365 Copilot", "sanctioned"),
    "chatgpt.com": ("ChatGPT (consumer)", "unsanctioned"),
    "claude.ai": ("Claude (consumer)", "unsanctioned"),
    "gemini.google.com": ("Gemini (consumer)", "unsanctioned"),
    "perplexity.ai": ("Perplexity", "unsanctioned"),
    "poe.com": ("Poe", "unsanctioned"),
    "deepseek.com": ("DeepSeek", "unsanctioned"),
    "character.ai": ("Character.AI", "unsanctioned"),
}
STATUS_WEIGHT = {"sanctioned": 0.1, "unsanctioned": 0.8, "suspected": 0.9}
_AI_HINT = re.compile(r"(gpt|llm|chatbot|copilot|aiwriter|ai-|-ai|\.ai$|genai|prompt)", re.I)


def classify(host: str):
    """Return (service, status, is_ai). status is None for non-AI hosts."""
    host = host.lower().rstrip(".")
    for suffix, (name, status) in CATALOG.items():
        if host == suffix or host.endswith("." + suffix):
            return name, status, True
    if _AI_HINT.search(host):
        return host, "suspected", True  # discovered, not in catalog
    return host, None, False


def load_policy(path):
    """Override catalog/weights from a JSON policy file (mutates in place so all modules see it).
    Returns the thresholds dict for analytics.configure()."""
    import json
    with open(path) as f:
        p = json.load(f)
    if "catalog" in p:
        CATALOG.clear()
        CATALOG.update({k: tuple(v) for k, v in p["catalog"].items()})
    STATUS_WEIGHT.update(p.get("status_weight", {}))
    return p.get("thresholds", {})
