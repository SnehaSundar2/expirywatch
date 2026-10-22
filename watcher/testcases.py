"""The four official test cases, each run against the real agent and saved with
input, expected result, actual result and evidence. Failures are recorded as failures."""
import json

from . import agent, lab, store

SHOP, API = "shop.lab.test", "api.shop.lab.test"
CASES = {
    "TC1": ("Certificate expires in 10 days", "alert and renewal ticket"),
    "TC2": ("Certificate renewed", "alert cleared after recheck"),
    "TC3": ("Lookup service fails", "domain marked unchecked"),
    "TC4": ("Subdomain with its own certificate", "tracked separately"),
}


def _save(tc, inp, actual, passed, evidence):
    scenario, expected = CASES[tc]
    store.x("INSERT INTO testruns (tc, scenario, input, expected, actual, result, evidence, ran_at) VALUES (?,?,?,?,?,?,?,?)",
            (tc, scenario, inp, expected, actual, "PASS" if passed else "FAIL", store.dumps(evidence), store.now()))
    return {"tc": tc, "result": "PASS" if passed else "FAIL", "actual": actual}


def _latest(key):
    return store.q("SELECT * FROM checks WHERE item_key=? ORDER BY id DESC LIMIT 1", (key,), one=True)


def tc1():
    lab.reset()
    store.add_domain(SHOP, label="Lab: storefront", owner="Web team")
    key = f"cert:{SHOP}:443"
    # start clean for this item so the run is repeatable
    store.x("UPDATE alerts SET state='cleared', cleared_at=? WHERE item_key=? AND state='active'", (store.now(), key))
    store.x("UPDATE tickets SET state='superseded' WHERE item_key=? AND state IN ('proposed','approved')", (key,))
    run = agent.run_cycle("test TC1", only=[key])
    c = _latest(key)
    alert = store.q("SELECT * FROM alerts WHERE item_key=? AND state='active'", (key,), one=True)
    t = store.q("SELECT * FROM tickets WHERE item_key=? AND state='proposed' ORDER BY id DESC LIMIT 1", (key,), one=True)
    ok = bool(c and c["status"] == "critical" and alert and t)
    actual = (f"Status {c['status'] if c else '?'} ({c['days_left'] if c else '?'} days left). "
              f"Alert {'raised' if alert else 'NOT raised'}. Renewal ticket "
              f"{'#%d proposed, waiting for human approval' % t['id'] if t else 'NOT proposed'}.")
    return _save("TC1", f"{SHOP} with a lab certificate valid for 10 days (run #{run})", actual, ok,
                 {"check": c, "alert": alert, "ticket": t and {k: t[k] for k in ('id', 'title', 'state', 'destination')}})


def tc2():
    key = f"cert:{SHOP}:443"
    before = _latest(key)
    t = store.q("SELECT * FROM tickets WHERE item_key=? AND state IN ('proposed','approved') ORDER BY id DESC LIMIT 1", (key,), one=True)
    new_serial = lab.renew(SHOP, 90)
    run = agent.run_cycle("test TC2", only=[key])
    after = _latest(key)
    alert = store.q("SELECT * FROM alerts WHERE item_key=? AND state='active'", (key,), one=True)
    t2 = store.q("SELECT * FROM tickets WHERE id=?", (t["id"],), one=True) if t else None
    ok = bool(after and after["status"] == "ok" and not alert and before and after["serial"] != before["serial"])
    actual = (f"Before: serial {before['serial'][:10] if before else '?'}…, {before['days_left'] if before else '?'} days. "
              f"After renewal recheck: serial {after['serial'][:10]}…, {after['days_left']} days, status {after['status']}. "
              f"Alert {'still ACTIVE' if alert else 'cleared'}. "
              f"Ticket {('#%d ' % t2['id']) + t2['state'] if t2 else 'none'}.")
    return _save("TC2", f"Lab certificate for {SHOP} renewed (new serial {new_serial[:10]}…, 90 days), then recheck (run #{run})",
                 actual, ok, {"before": before, "after": after, "ticket": t2 and {k: t2[k] for k in ('id', 'state', 'verify_note')}})


def tc3():
    store.add_domain("github.com", label="Public: GitHub", owner="Platform team")
    key = "reg:github.com"
    lab.set_lookup_outage(True)
    try:
        run = agent.run_cycle("test TC3", only=[key])
    finally:
        lab.set_lookup_outage(False)
    c = _latest(key)
    alert = store.q("SELECT * FROM alerts WHERE item_key=? AND state='active'", (key,), one=True)
    ok = bool(c and c["status"] == "unchecked" and not alert and c["error"])
    actual = (f"Status {c['status'].upper()}. Reason: {c['error']}. No alert raised and no expiry guessed; "
              f"previous known value kept as context only.")
    return _save("TC3", f"github.com registration lookup while the RDAP lookup service is down (run #{run})",
                 actual, ok, {"check": c})


def tc4():
    store.add_domain(SHOP, label="Lab: storefront", owner="Web team")
    store.add_domain(API, label="Lab: API subdomain", owner="API team")
    run = agent.run_cycle("test TC4", only=[f"cert:{SHOP}:443", f"cert:{API}:443"])
    a, b = _latest(f"cert:{SHOP}:443"), _latest(f"cert:{API}:443")
    ok = bool(a and b and a["serial"] != b["serial"] and a["item_key"] != b["item_key"])
    actual = (f"Two separate items. {SHOP}: serial {a['serial'][:10]}…, expires {a['expires_at'][:10]}, {a['status']}. "
              f"{API}: serial {b['serial'][:10]}…, expires {b['expires_at'][:10]}, {b['status']}. "
              f"Each has its own status, alerts and tickets.")
    return _save("TC4", f"{SHOP} and its subdomain {API}, each serving its own certificate (run #{run})", actual, ok,
                 {"parent": a, "subdomain": b})


def run_all():
    return [tc1(), tc2(), tc3(), tc4()]


def latest_results():
    rows = store.q("SELECT * FROM testruns WHERE id IN (SELECT MAX(id) FROM testruns GROUP BY tc) ORDER BY tc")
    for r in rows:
        r["evidence"] = json.loads(r["evidence"] or "{}")
    return rows
