"""Synthetic prompt corpus. Used to simulate traffic AND to bootstrap the sensitivity model.
Replace with labelled, consented real data in production (see README)."""
import random

DEPTS = ["Engineering", "Finance", "HR", "Marketing", "Support", "Legal"]
_CUST = ["Acme Corp", "Globex", "Initech", "Umbrella Ltd", "Hooli", "Stark Retail"]
_PROJ = ["Falcon", "Orion", "Atlas", "Nimbus", "Helix"]
_TOPIC = ["renewable energy", "remote work", "electric cars", "supply chains", "cloud pricing", "space tourism"]

TEMPLATES = {
    "public": [
        "summarize this news article about {topic} in three bullet points",
        "explain the difference between tcp and udp for a beginner",
        "write a polite email declining a meeting invitation",
        "translate this paragraph about {topic} into spanish",
        "give me ten catchy blog titles about {topic}",
        "what is the history of {topic} and why does it matter",
        "help me write a cover letter and improve my resume for a job application",
        "how do i convert units or calculate a percentage in everyday life",
        "suggest names, gift ideas or a travel plan for a weekend trip",
        "explain how {topic} works in simple terms for a student",
        "draft a thank you note or birthday message to a friend",
        "compare two programming languages or tools for a beginner",
    ],
    "internal": [
        "rewrite this internal announcement about the {proj} team offsite schedule",
        "draft an agenda for the weekly sync on project {proj}",
        "turn these meeting notes from the {proj} standup into action items",
        "make this onboarding checklist for new hires friendlier",
        "clean up the wording of our team lunch or office hours reminder message",
        "create a slide outline for the {proj} project kickoff meeting",
        "summarize the notes from yesterday's sprint planning and retrospective",
        "write a welcome message for the new intern cohort and reword the holiday schedule memo",
        "prepare questions for the {proj} status meeting with the staff",
    ],
    "confidential": [
        "analyze our q3 revenue forecast and churn risk for customer {cust}",
        "summarize the draft merger term sheet and flag unusual clauses",
        "review salary bands and compensation for the engineering promotion cycle",
        "customer contract renewal pricing and discount approval for {cust}",
        "board deck notes on unreleased earnings and layoffs under project {proj}",
        "critique our unreleased product pricing strategy and confidential roadmap",
        "evaluate acquisition target financials and valuation received under nda",
        "phrase the termination package and severance for the employee in the restructuring",
        "summarize confidential audit findings, legal settlement offer and pending lawsuit",
        "compare the exclusive reseller agreement terms and suggest concessions to the partner",
        "analyze top accounts contract values, customer revenue and churn",
    ],
    "source_code": [
        "fix this bug in our function def process_payment(order): return order.total",
        "why does this sql query SELECT * FROM prod_customers JOIN orders time out",
        "refactor this class public class InvoiceService import java.util.List",
        "optimize this loop for (int i = 0; i < n; i++) {{ cache.put(key, value); }}",
        "write unit tests for this module import requests def fetch_token(url):",
        "this python function throws an error def load(path): return json.load(open(path))",
        "debug a null pointer in this java method public void save(User u) {{ repo.save(u); }}",
        "rewrite this bash script for i in $(ls); do echo $i; done and convert it to python",
        "convert this javascript const add = (a, b) => a + b to typescript and fix the failing test assert x == 1",
        "what is wrong with this regex, docker compose yaml, json or stack trace exception",
        "my sql join is slow SELECT o.id FROM orders o JOIN customers c ON o.cid = c.id",
    ],
}


def sample(category: str, rng: random.Random) -> str:
    t = rng.choice(TEMPLATES[category])
    return t.format(topic=rng.choice(_TOPIC), proj=rng.choice(_PROJ), cust=rng.choice(_CUST))
