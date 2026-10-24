# Operation Shadow R2 – Trace the Attack
Timeline correlation + triage tool (fictional evidence only, Python stdlib).
- `python tracer.py [csv]` → prints and writes `summary.md` (default: `case_file.csv`; also try `variant_a.csv`)
- `pytest` → 8 tests
- `ui/index.html` → open in a browser (needs internet only for Google Fonts)

Logic: orders events, tags FACT vs HYPOTHESIS, scores indicator strength 0–3, maps attack stages, flags assumptions with what would confirm them, and only reports exfiltration as CONFIRMED when a download/transfer/egress event is observed. Previews and a forwarding rule are access/capability, not proof.
Limits: keyword-based scoring, tiny dataset, no log sources beyond the case file.
