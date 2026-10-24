#!/usr/bin/env python3
"""Operation Shadow R2 - timeline correlation & triage tool (fictional evidence only).
Usage: python tracer.py [csv]  (default case_file.csv)  -> prints and writes summary.md"""
import csv, sys, os, re

# keyword -> (indicator strength 0-3, attack stage)
INDICATORS = [
    (r"forwarding rule.*(created|external)|external.*forwarding", 3, "Persistence"),
    (r"user denies|did not initiate", 3, "Credential / MFA abuse"),
    (r"mfa passed after", 2, "Credential / MFA abuse"),
    (r"unfamiliar ip|new browser|new device", 2, "Initial access"),
    (r"payroll-themed|phishing", 2, "Delivery"),
    (r"recovery settings viewed", 2, "Account takeover recon"),
    (r"preview", 1, "Collection (access only)"),
    (r"sign-in attempt.*fails", 1, "Possible lockout"),
]
EXFIL_PROOF = re.compile(r"download(ed)?\b|exported|outbound transfer|forwarded message|data sent|egress", re.I)
RESPONSE = re.compile(r"disables|blocks|removed|reports", re.I)

def load(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        evs = list(csv.DictReader(f))
    mins = lambda t: int(t[:2]) * 60 + int(t[3:])
    evs.sort(key=lambda e: mins(e["time"]))
    for e in evs:
        e["strength"], e["stage"] = 0, "Context"
        if e["status"] == "observed" or e["status"] == "response":
            for pat, s, st in INDICATORS:
                if re.search(pat, e["event"], re.I):
                    e["strength"], e["stage"] = s, st; break
        if e["status"] == "unconfirmed":
            e["stage"] = "Hypothesis"
        if e["status"] == "response" or (e["status"] == "observed" and RESPONSE.search(e["event"]) and e["strength"] == 0):
            e["stage"] = "Response"
        e["fact"] = e["status"] in ("observed", "response")
    return evs

def exfil_verdict(evs):
    proof = [e for e in evs if e["fact"] and EXFIL_PROOF.search(e["event"]) and not re.search(r"no (confirmed )?download", e["event"], re.I)]
    if proof: return "CONFIRMED", [e["event_id"] for e in proof]
    access = [e["event_id"] for e in evs if e["fact"] and "preview" in e["event"].lower()]
    persist = [e["event_id"] for e in evs if e["fact"] and "forwarding rule" in e["event"].lower()]
    return ("UNCONFIRMED", access + persist)

NEEDED = [
    "File-portal download/export logs for the 08:44 session (a preview is not a download)",
    "Mail transport logs for messages matching the forwarding rule between creation and removal, plus its destination",
    "Proxy / DLP / network egress logs for the user and session IP during the window",
    "Correlation of the previews and rule creation to the same session ID/IP as the unfamiliar sign-in",
    "Identity and sensitivity of the previewed documents",
    "Mira's statement that she did not preview those documents herself",
]
def assumptions(evs):
    ids = {e["event_id"]: e for e in evs}; out = []
    txt = " ".join(e["event"].lower() for e in evs)
    if "unfamiliar" in txt and "payroll" in txt:
        out.append(("Phish led to credential theft", "Timing only (3 min); order does not prove causation", "Headers, link click and credential-submission logs"))
    if "denies" in txt:
        out.append(("Attacker obtained the MFA approval (prompt fatigue or social engineering)", "User denial plus unfamiliar sign-in", "Approver device/IP and prompt logs"))
    if "forwarding" in txt:
        out.append(("Forwarding rule was meant to exfiltrate mail", "External destination rule created minutes after sign-in", "Rule destination and forwarded-message logs"))
    if "preview" in txt:
        out.append(("Previews were attacker reconnaissance", "Previews followed the suspicious session", "Session/IP attribution of the previews"))
    if "fails" in txt:
        out.append(("Office sign-in failed because the attacker changed credentials", "Failure soon after compromise", "Failure reason in identity logs"))
    if not out:
        out.append(("Account may be compromised", "Chain of new device, MFA anomaly and recovery view", "User confirmation and auth context"))
    return out

def response_plan(evs):
    txt = " ".join(e["event"].lower() for e in evs)
    done = lambda k: k in txt
    plan = [
        ("P0", "Disable active sessions and block sign-in pending identity verification", done("disables")),
        ("P0", "Remove external forwarding rule(s); record destination first for evidence", done("rule removed")),
        ("P1", "Preserve logs (identity, mail, file portal, proxy) before retention rolls over", False),
        ("P1", "Verify Mira's identity out-of-band; then reset password and re-register MFA", False),
        ("P1", "Hunt: forwarded mail, downloads and egress in the exposure window (see evidence gaps)", False),
        ("P2", "Audit other inbox rules, delegates, OAuth grants and recovery settings", False),
        ("P2", "Purge the phishing email from other mailboxes; block sender/domain", False),
        ("P3", "Decide on notification only after exfiltration is confirmed or ruled out", False),
        ("P3", "Enable number matching / phishing-resistant MFA; staff awareness note", False),
    ]
    return plan

def summary(evs):
    v, basis = exfil_verdict(evs)
    top = sorted([e for e in evs if e["strength"]], key=lambda e: -e["strength"])[:3]
    L = ["# Operation Shadow R2 - Incident Summary", "", f"**Data exfiltration: {v}**" + (f" (basis: {', '.join(basis)} are access/capability, not transfer)" if v == "UNCONFIRMED" else ""), "",
         "## Timeline", "", "| ID | Time | Event | Type | Strength | Stage | Evidence gap |", "|---|---|---|---|---|---|---|"]
    L += [f"| {e['event_id']} | {e['time']} | {e['event']} | {'FACT' if e['fact'] else 'HYPOTHESIS'} | {e['strength']}/3 | {e['stage']} | {e['evidence_gap']} |" for e in evs]
    L += ["", "## Strongest indicators", *[f"- {e['event_id']} {e['event']} ({e['stage']})" for e in top]]
    L += ["", "## Likely attack path (hypothesis)", " -> ".join(dict.fromkeys(e["stage"] for e in evs if e["strength"])),
          "", "## Assumptions to verify", "", "| Assumption | Basis | Would confirm it |", "|---|---|---|"]
    L += [f"| {a} | {b} | {c} |" for a, b, c in assumptions(evs)]
    L += ["", "## Prioritized response", *[f"- [{'x' if d else ' '}] **{p}** {t}" for p, t, d in response_plan(evs)]]
    L += ["", "## Evidence needed before claiming exfiltration", *[f"{i}. {n}" for i, n in enumerate(NEEDED, 1)],
          "", "Confidence: high that the session was unauthorized-looking, medium on attacker intent, low on any data loss."]
    return "\n".join(L)

if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    evs = load(sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "case_file.csv"))
    md = summary(evs); print(md); open(os.path.join(here, "summary.md"), "w").write(md)
