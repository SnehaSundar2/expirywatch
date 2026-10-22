"""ExpiryWatch web app. Run: python app.py, then open http://127.0.0.1:5000"""
import json
import os
import threading
from collections import OrderedDict
from datetime import datetime, timezone

from dotenv import load_dotenv
from flask import Flask, Response, jsonify, redirect, render_template, request

load_dotenv()
from watcher import agent, lab, llm, store, testcases  # noqa: E402

app = Flask(__name__)


@app.context_processor
def globals_():
    return {"ai": llm.available(), "model": llm.model_name()}
SEED = [("github.com", "Public: GitHub", "Platform team"), ("google.com", "Public: Google", "Platform team"),
        ("www.iitm.ac.in", "Public: IIT Madras", "Campus IT"), ("expired.badssl.com", "Public: deliberately expired cert", "Security team"),
        ("shop.lab.test", "Lab: storefront", "Web team"), ("api.shop.lab.test", "Lab: API subdomain", "API team")]


def boot():
    store.init()
    lab.start()
    if not store.q("SELECT id FROM domains LIMIT 1"):
        for host, label, owner in SEED:
            store.add_domain(host, label=label, owner=owner)
        threading.Thread(target=agent.run_cycle, args=("startup",), daemon=True).start()
    agent.scheduler(float(os.getenv("CHECK_INTERVAL_MIN", "60")))


def state():
    latest = store.latest_checks()
    domains = {d["id"]: d for d in store.q("SELECT * FROM domains")}
    alerts = {a["item_key"]: a for a in store.q("SELECT * FROM alerts WHERE state='active'")}
    tickets = store.q("SELECT * FROM tickets ORDER BY id DESC")
    open_t = {t["item_key"]: t for t in tickets if t["state"] in ("proposed", "approved")}
    rows = []
    for c in latest:
        prev = store.last_good(c["item_key"]) if c["status"] == "unchecked" else None
        c["evidence"] = json.loads(c["evidence"] or "{}")
        c["target"] = c["item_key"].split(":")[1]
        c["domain"] = domains.get(c["domain_id"], {})
        c["alert"] = alerts.get(c["item_key"])
        c["ticket"] = open_t.get(c["item_key"])
        c["prev"] = prev
        rows.append(c)
    # expiry calendar: group by month
    cal = OrderedDict()
    for c in sorted([r for r in rows if r["expires_at"] or (r["prev"] and r["prev"]["expires_at"])],
                    key=lambda r: r["expires_at"] or r["prev"]["expires_at"]):
        exp = c["expires_at"] or c["prev"]["expires_at"]
        d = datetime.fromisoformat(exp)
        month = "Already expired" if d < datetime.now(timezone.utc) else d.strftime("%B %Y")
        cal.setdefault(month, []).append({"date": d.strftime("%d %b %Y"), "row": c, "stale": not c["expires_at"]})
    return rows, cal, tickets


@app.get("/")
def index():
    rows, cal, tickets = state()
    events = store.q("SELECT * FROM events ORDER BY id DESC LIMIT 60")
    last_run = store.q("SELECT * FROM runs ORDER BY id DESC LIMIT 1", one=True)
    stats = {"watched": len(rows), "alerts": sum(1 for r in rows if r["alert"]),
             "approval": sum(1 for t in tickets if t["state"] == "proposed"),
             "unchecked": sum(1 for r in rows if r["status"] == "unchecked")}
    return render_template("index.html", rows=rows, cal=cal, tickets=tickets, events=events, stats=stats,
                           last_run=last_run, ai=llm.available(), model=llm.model_name(), dest=agent.destination(),
                           thresholds=(agent.CERT_WARN, agent.CERT_CRIT, agent.DOM_WARN, agent.DOM_CRIT))


@app.get("/tests")
def tests():
    return render_template("tests.html", results={r["tc"]: r for r in testcases.latest_results()}, cases=testcases.CASES,
                           pending=store.q("SELECT * FROM tickets WHERE state='proposed' AND item_key=?",
                                           (f"cert:{testcases.SHOP}:443",)))


@app.post("/api/run")
def api_run():
    rid = agent.run_cycle("manual")
    return jsonify(ok=rid is not None, run=rid, msg=None if rid else "A run is already in progress")


@app.post("/api/domains")
def api_add():
    f = request.form
    try:
        did = store.add_domain(f.get("host"), f.get("port") or 443, f.get("label", ""), f.get("owner") or "DevOps")
    except ValueError as e:
        return redirect("/?error=" + str(e))
    agent.run_cycle("manual", only=[did])
    return redirect("/#items")


@app.post("/api/domains/<did>/remove")
def api_remove(did):
    store.x("UPDATE domains SET enabled=0 WHERE id=?", (did,))
    return redirect("/#items")


@app.post("/api/tickets/<int:tid>/<decision>")
def api_ticket(tid, decision):
    who = (request.form.get("who") or "Ops reviewer").strip()[:60]
    try:
        _, msg = agent.decide_ticket(tid, decision == "approve", who)
    except Exception as e:
        msg = f"Failed: {e}"
    return redirect(f"{request.form.get('back', '/')}?msg={msg}#approvals")


@app.post("/api/tests/<tc>")
def api_test(tc):
    fn = {"TC1": testcases.tc1, "TC2": testcases.tc2, "TC3": testcases.tc3, "TC4": testcases.tc4}.get(tc)
    if tc == "all":
        testcases.run_all()
    elif fn:
        fn()
    return redirect("/tests#" + tc)


@app.post("/api/lab/reset")
def api_lab_reset():
    lab.reset()
    return redirect("/tests")


@app.get("/calendar.ics")
def ics():
    rows, _, _ = state()
    out = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//ExpiryWatch//EN", "X-WR-CALNAME:ExpiryWatch expiries"]
    for r in rows:
        if not r["expires_at"]:
            continue
        d = datetime.fromisoformat(r["expires_at"]).strftime("%Y%m%d")
        what = "SSL certificate" if r["kind"] == "cert" else "Domain registration"
        out += ["BEGIN:VEVENT", f"UID:{r['item_key']}@expirywatch", f"DTSTART;VALUE=DATE:{d}",
                f"SUMMARY:{what} expires: {r['target']}", f"DESCRIPTION:Status {r['status']}. Source: {r['source']}",
                "BEGIN:VALARM", "TRIGGER:-P14D", "ACTION:DISPLAY", f"DESCRIPTION:{r['target']} expires in 14 days", "END:VALARM",
                "END:VEVENT"]
    out.append("END:VCALENDAR")
    return Response("\r\n".join(out), mimetype="text/calendar",
                    headers={"Content-Disposition": "attachment; filename=expirywatch.ics"})


@app.get("/api/ai-check")
def ai_check():
    if not llm.available():
        return jsonify(ok=False, msg="No AI key configured")
    return jsonify(llm.diagnose())


@app.get("/api/state")
def api_state():
    rows, _, tickets = state()
    return jsonify(items=[{k: r[k] for k in ("item_key", "status", "expires_at", "days_left", "source", "error")} for r in rows],
                   tickets=[{k: t[k] for k in ("id", "item_key", "state", "title", "destination", "external_ref")} for t in tickets])


boot()

if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    print(f"ExpiryWatch is running. Open http://127.0.0.1:{port}")
    app.run(host="0.0.0.0" if os.getenv("PORT") else "127.0.0.1", port=port, debug=False, threaded=True)
