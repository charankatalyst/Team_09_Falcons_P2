import os
from tracer import *
D = os.path.dirname(os.path.abspath(__file__))
case = load(os.path.join(D, "case_file.csv")); va = load(os.path.join(D, "variant_a.csv"))
def test_order(): assert [e["time"] for e in case] == sorted(e["time"] for e in case)
def test_exfil_unconfirmed_case(): assert exfil_verdict(case)[0] == "UNCONFIRMED"
def test_exfil_unconfirmed_variant(): assert exfil_verdict(va)[0] == "UNCONFIRMED"
def test_hypothesis_not_fact(): assert not [e for e in va if e["event_id"] == "TA-205"][0]["fact"]
def test_previews_weak(): assert [e for e in case if "preview" in e["event"]][0]["strength"] == 1
def test_forwarding_strong(): assert max(case, key=lambda e: e["strength"])["strength"] == 3
def test_response_done(): assert [p for p in response_plan(case) if "Disable" in p[1]][0][2]
def test_confirmed_when_download():
    c = [dict(event_id="X", time="10:00", event="File downloaded by session", status="observed", fact=True, strength=0, stage="", evidence_gap="")]
    assert exfil_verdict(c)[0] == "CONFIRMED"
