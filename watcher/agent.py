"""ExpiryWatch agent.

Each run: PLAN which items to check (LLM, with rule fallback and guard rails)
-> GATHER evidence with tools (TLS handshake, RDAP lookup) -> DECIDE with
explicit rules (days to expiry) -> ACT by proposing a renewal ticket that waits
for human approval -> VERIFY approved tickets by rechecking after renewal."""
import json
import os
import threading
from datetime import datetime, timezone

import requests

from . import checks, lab, llm, store

CERT_WARN, CERT_CRIT = int(os.getenv("CERT_WARN_DAYS", "30")), int(os.getenv("CERT_CRIT_DAYS", "14"))
DOM_WARN, DOM_CRIT = int(os.getenv("DOMAIN_WARN_DAYS", "60")), int(os.getenv("DOMAIN_CRIT_DAYS", "30"))
RECHECK_HEALTHY_HOURS = float(os.getenv("RECHECK_HEALTHY_HOURS", "12"))
_run_lock = threading.Lock()


# ---------------------------------------------------------------- items
def items():
    """Every thing we watch: one certificate per host:port, one registration per registrable domain."""
    out, seen_reg = [], set()
    for d in store.q("SELECT * FROM domains WHERE enabled=1 ORDER BY created_at"):
        out.append({"key": f"cert:{d['host']}:{d['port']}", "kind": "cert", "domain_id": d["id"],
                    "target": d["host"], "port": d["port"], "connect": d["connect_addr"], "owner": d["owner"]})
        if lab.is_lab_host(d["host"]):
            continue
        reg = checks.registrable_domain(d["host"])
        if reg not in seen_reg:
            seen_reg.add(reg)
            out.append({"key": f"reg:{reg}", "kind": "registration", "domain_id": d["id"], "target": reg,
                        "owner": d["owner"]})
    return out


def classify(kind, days_left):
    """Explicit decision rule: days to expiry -> status."""
    if days_left is None:
        return "unchecked"
    warn, crit = (CERT_WARN, CERT_CRIT) if kind == "cert" else (DOM_WARN, DOM_CRIT)
    if days_left < 0:
        return "expired"
    if days_left <= crit:
        return "critical"
    if days_left <= warn:
        return "warning"
    return "ok"


def _hours_since(ts):
    if not ts:
        return 1e9
    return (datetime.now(timezone.utc) - datetime.fromisoformat(ts)).total_seconds() / 3600


# ---------------------------------------------------------------- plan
PLAN_PROMPT = """You are ExpiryWatch, an operations agent that prevents SSL certificate and domain expiry outages.
Decide which items to check in this run. You get each item's last known state.
Guidelines: check anything never checked, unchecked (last lookup failed), alerting, near expiry, or with an
approved renewal ticket waiting for verification. Healthy items checked recently can be skipped to save calls.
For a manual run, prefer checking everything unless clearly unnecessary.
Reply with JSON only: {"thought": "...", "plan": [{"key": "<item key>", "action": "check" | "skip", "reason": "..."}]}"""


def plan(trigger, its, run_id):
    last = {c["item_key"]: c for c in store.latest_checks()}
    approved = {t["item_key"] for t in store.q("SELECT item_key FROM tickets WHERE state='approved'")}
    active = {a["item_key"] for a in store.q("SELECT item_key FROM alerts WHERE state='active'")}
    rows = [{"key": i["key"], "kind": i["kind"], "last_status": (last.get(i["key"]) or {}).get("status", "never checked"),
             "days_left": (last.get(i["key"]) or {}).get("days_left"),
             "hours_since_check": round(min(_hours_since((last.get(i["key"]) or {}).get("checked_at")), 9999), 1),
             "alert_active": i["key"] in active, "approved_ticket_waiting": i["key"] in approved} for i in its]
    decided, planner = None, "rules"
    if llm.available():
        try:
            out = llm.chat_json(PLAN_PROMPT, f"Trigger: {trigger}\nItems: {json.dumps(rows)}")
            decided = {p["key"]: p for p in out.get("plan", []) if p.get("key")}
            planner = f"AI ({llm.model_name()})"
            store.event("think", out.get("thought", ""), run_id)
        except Exception as e:
            store.event("warn", f"AI planner failed ({e}); using rule planner", run_id)
    final = []
    for r in rows:
        must = (r["last_status"] in ("never checked", "unchecked", "warning", "critical", "expired")
                or r["alert_active"] or r["approved_ticket_waiting"])
        if decided is not None and r["key"] in decided:
            p = decided[r["key"]]
            if p.get("action") == "skip" and must:  # guard rail: never skip something risky
                p = {"action": "check", "reason": "guard rail: item is risky or unverified, so it is always checked"}
        else:
            stale = r["hours_since_check"] >= RECHECK_HEALTHY_HOURS
            p = {"action": "check" if (must or stale or trigger == "manual") else "skip",
                 "reason": "risky/unverified" if must else "manual run" if trigger == "manual" else
                           "due for routine recheck" if stale else f"healthy and checked {r['hours_since_check']}h ago"}
        final.append({"key": r["key"], "action": p.get("action", "check"), "reason": p.get("reason", "")})
    return final, planner


# ---------------------------------------------------------------- gather + decide
def gather(item, run_id):
    try:
        fn = (lambda: checks.tls_check(item["target"], item["port"], item["connect"])) if item["kind"] == "cert"             else (lambda: checks.rdap_check(item["target"]))
        try:
            res = fn()
        except checks.CheckFailed as first:
            if "simulated outage" in str(first) or "DNS lookup failed" in str(first):
                raise
            store.event("retry", f"{item['key']}: {first} — retrying once", run_id, item["key"])
            res = fn()
        status = classify(item["kind"], res["days_left"])
        cid = store.x("""INSERT INTO checks (item_key, domain_id, kind, run_id, checked_at, status, expires_at, days_left,
                         serial, issuer, subject, source, evidence) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                      (item["key"], item["domain_id"], item["kind"], run_id, store.now(), status, res["expires_at"],
                       res["days_left"], res["serial"], res["issuer"], res["subject"], res["source"], store.dumps(res["evidence"])))
        store.event("check", f"{item['key']}: {status.upper()} — expires {res['expires_at'][:10]} "
                             f"({res['days_left']:.0f} days)", run_id, item["key"])
        return cid, status, res
    except checks.CheckFailed as e:
        prev = store.last_good(item["key"])
        ev = {"previous_known": {"expires_at": prev["expires_at"], "checked_at": prev["checked_at"]} if prev else None}
        cid = store.x("""INSERT INTO checks (item_key, domain_id, kind, run_id, checked_at, status, source, evidence, error)
                         VALUES (?,?,?,?,?,?,?,?,?)""",
                      (item["key"], item["domain_id"], item["kind"], run_id, store.now(), "unchecked",
                       "lookup failed", store.dumps(ev), str(e)))
        store.event("unchecked", f"{item['key']}: marked UNCHECKED — {e}. No alert raised or cleared on missing evidence.",
                    run_id, item["key"])
        return cid, "unchecked", None


def update_alert(item, status, check_id, res, run_id):
    active = store.q("SELECT * FROM alerts WHERE item_key=? AND state='active'", (item["key"],), one=True)
    if status == "unchecked":
        return  # uncertain: keep whatever state we had
    if status in ("warning", "critical", "expired"):
        reason = f"{'Certificate' if item['kind'] == 'cert' else 'Domain registration'} for {item['target']} " \
                 f"{'has EXPIRED' if status == 'expired' else 'expires in %.0f days' % res['days_left']} ({res['expires_at'][:10]})"
        if active:
            store.x("UPDATE alerts SET severity=?, reason=? WHERE id=?", (status, reason, active["id"]))
        else:
            store.x("""INSERT INTO alerts (item_key, domain_id, kind, state, severity, reason, opened_at, opened_check)
                       VALUES (?,?,?,?,?,?,?,?)""", (item["key"], item["domain_id"], item["kind"], "active", status,
                                                     reason, store.now(), check_id))
            store.event("alert", f"ALERT raised: {reason}", run_id, item["key"])
            notify(f"⚠️ ExpiryWatch alert: {reason}")
    elif active:
        store.x("UPDATE alerts SET state='cleared', cleared_at=?, cleared_check=? WHERE id=?",
                (store.now(), check_id, active["id"]))
        store.event("cleared", f"Alert cleared for {item['target']}: recheck shows expiry {res['expires_at'][:10]} "
                               f"({res['days_left']:.0f} days)", run_id, item["key"])
        notify(f"✅ ExpiryWatch: alert cleared for {item['target']} (now valid until {res['expires_at'][:10]})")


# ---------------------------------------------------------------- act
TICKET_PROMPT = """You are ExpiryWatch, writing a renewal ticket for an operations team. Be concrete and short.
Use only the facts given. Include: what expires and when, impact if missed, and 3-5 renewal steps that fit the
issuer/registrar (e.g. Let's Encrypt -> check certbot/ACME auto-renew; commercial CA -> reissue and install;
domain -> renew at the registrar, check auto-renew and payment method). End with how ExpiryWatch will verify.
Reply with JSON only: {"title": "...", "body": "..."}"""


def destination():
    if os.getenv("GITHUB_TOKEN") and os.getenv("GITHUB_REPO"):
        return f"GitHub Issues: {os.environ['GITHUB_REPO']}"
    return "ExpiryWatch ticket board (built-in)"


def propose_ticket(item, status, check_id, res, run_id):
    if status not in ("critical", "expired"):
        return
    # Idempotency: one ticket per item per specific certificate / expiry date. Retries never duplicate it.
    idem = f"{item['key']}|{res['serial'] or res['expires_at'][:10]}"
    if store.q("SELECT id FROM tickets WHERE idem_key=?", (idem,), one=True):
        return
    if store.q("SELECT id FROM tickets WHERE item_key=? AND state IN ('proposed','approved')", (item["key"],), one=True):
        return
    what = "SSL certificate" if item["kind"] == "cert" else "Domain registration"
    facts = {"item": item["key"], "what": what, "target": item["target"], "status": status,
             "expires_at": res["expires_at"], "days_left": res["days_left"], "issuer_or_registrar": res["issuer"],
             "source": res["source"], "owner_team": item["owner"]}
    title = f"[{status.upper()}] Renew {what.lower()} for {item['target']} (expires {res['expires_at'][:10]})"
    body = (f"{what} for {item['target']} {'has expired' if status == 'expired' else 'expires in %.0f days' % res['days_left']} "
            f"on {res['expires_at'][:10]}.\n\nIssuer/registrar: {res['issuer'] or 'unknown'}\nEvidence: {res['source']}\n\n"
            f"Steps:\n1. Renew/reissue with {res['issuer'] or 'the provider'}.\n2. Install the new certificate / confirm renewal.\n"
            f"3. Enable auto-renew if available.\n\nExpiryWatch will recheck after renewal and close this ticket only when "
            f"the new expiry date is confirmed.")
    if llm.available():
        try:
            out = llm.chat_json(TICKET_PROMPT, json.dumps(facts))
            title, body = out.get("title") or title, out.get("body") or body
        except Exception as e:
            store.event("warn", f"AI ticket drafting failed ({e}); using template", run_id)
    prio = "P1" if status == "expired" or res["days_left"] <= 7 else "P2"
    store.x("""INSERT INTO tickets (idem_key, item_key, domain_id, kind, state, destination, title, body, priority,
               created_at, check_id) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (idem, item["key"], item["domain_id"], item["kind"], "proposed", destination(), title, body, prio,
             store.now(), check_id))
    store.event("propose", f"Renewal ticket PROPOSED for {item['target']} → waiting for human approval", run_id, item["key"])


def decide_ticket(ticket_id, approve, who):
    """Human approval step. Opening a ticket is the only outward action, and it happens only here."""
    t = store.q("SELECT * FROM tickets WHERE id=?", (ticket_id,), one=True)
    if not t:
        raise ValueError("Ticket not found")
    if t["state"] != "proposed":
        return t, f"Already {t['state']} — nothing done again (duplicate protection)"
    if not approve:
        store.x("UPDATE tickets SET state='rejected', decided_at=?, decided_by=? WHERE id=?", (store.now(), who, ticket_id))
        store.event("rejected", f"Ticket #{ticket_id} rejected by {who}", None, t["item_key"])
        return t, "Rejected"
    snapshot = {k: t[k] for k in ("destination", "title", "body", "priority", "idem_key")}
    ref = open_external(t)
    store.x("""UPDATE tickets SET state='approved', decided_at=?, decided_by=?, approved_snapshot=?, external_ref=?
               WHERE id=? AND state='proposed'""", (store.now(), who, store.dumps(snapshot), ref, ticket_id))
    store.event("opened", f"Ticket #{ticket_id} approved by {who} and opened at {t['destination']}"
                          + (f" ({ref})" if ref else ""), None, t["item_key"])
    return t, "Opened"


def open_external(t):
    if not (os.getenv("GITHUB_TOKEN") and os.getenv("GITHUB_REPO")):
        return f"EW-{t['id']}"
    r = requests.post(f"https://api.github.com/repos/{os.environ['GITHUB_REPO']}/issues",
                      headers={"Authorization": "Bearer " + os.environ["GITHUB_TOKEN"],
                               "Accept": "application/vnd.github+json"},
                      json={"title": t["title"], "body": t["body"] + f"\n\n<!-- expirywatch:{t['idem_key']} -->",
                            "labels": ["expirywatch", t["priority"]]}, timeout=20)
    r.raise_for_status()
    return r.json()["html_url"]


# ---------------------------------------------------------------- verify
def verify(item, status, res, check_id, run_id):
    if status == "ok":  # a proposal nobody approved is no longer needed once the item is healthy again
        for p in store.q("SELECT id FROM tickets WHERE item_key=? AND state='proposed'", (item["key"],)):
            store.x("UPDATE tickets SET state='withdrawn', verify_note=? WHERE id=?",
                    (f"Withdrawn {store.now()[:16]}: recheck shows it was renewed before approval", p["id"]))
            store.event("withdrawn", f"Ticket #{p['id']} withdrawn — no longer needed", run_id, item["key"])
    t = store.q("SELECT * FROM tickets WHERE item_key=? AND state='approved'", (item["key"],), one=True)
    if not t:
        return
    if status == "unchecked":
        store.x("UPDATE tickets SET verify_note=? WHERE id=?", (f"{store.now()[:16]}: recheck could not run — still pending", t["id"]))
        return
    snap = json.loads(t["approved_snapshot"] or "{}")
    old = snap.get("idem_key", "").split("|")[-1]
    new_id = res["serial"] or res["expires_at"][:10]
    if status == "ok" and new_id != old:
        note = f"Verified {store.now()[:16]}: new {'certificate (serial ' + res['serial'][:12] + '…)' if res['serial'] else 'expiry'} " \
               f"valid until {res['expires_at'][:10]} ({res['days_left']:.0f} days)"
        store.x("UPDATE tickets SET state='resolved', verified_at=?, verify_note=? WHERE id=?", (store.now(), note, t["id"]))
        store.event("verified", f"Ticket #{t['id']} RESOLVED — {note}", run_id, item["key"])
    else:
        note = f"Recheck {store.now()[:16]}: not renewed yet (still expires {res['expires_at'][:10]}, {res['days_left']:.0f} days)"
        store.x("UPDATE tickets SET verify_note=? WHERE id=?", (note, t["id"]))
        store.event("pending", f"Ticket #{t['id']} still open — {note}", run_id, item["key"])


# ---------------------------------------------------------------- run
def notify(text):
    url = os.getenv("ALERT_WEBHOOK_URL")
    if not url:
        return
    try:
        requests.post(url, json={"text": text, "content": text}, timeout=8)
    except Exception:
        pass


def run_cycle(trigger="manual", only=None):
    if not _run_lock.acquire(blocking=False):
        return None
    try:
        run_id = store.x("INSERT INTO runs (trigger, started_at) VALUES (?,?)", (trigger, store.now()))
        its = [i for i in items() if not only or i["key"] in only or i["domain_id"] in only]
        store.event("start", f"Run #{run_id} started ({trigger}) — {len(its)} items to consider", run_id)
        steps, planner = plan(trigger if not only else "manual", its, run_id)
        store.x("UPDATE runs SET planner=?, plan=? WHERE id=?", (planner, store.dumps(steps), run_id))
        for s in steps:
            store.event("plan", f"{s['action'].upper()} {s['key']} — {s['reason']}", run_id, s["key"])
        counts = {}
        for item in its:
            if next((s for s in steps if s["key"] == item["key"]), {}).get("action") != "check":
                continue
            cid, status, res = gather(item, run_id)
            counts[status] = counts.get(status, 0) + 1
            update_alert(item, status, cid, res, run_id)
            if res:
                propose_ticket(item, status, cid, res, run_id)
            verify(item, status, res, cid, run_id)
        summary = ", ".join(f"{v} {k}" for k, v in sorted(counts.items())) or "nothing needed checking"
        store.x("UPDATE runs SET finished_at=?, summary=? WHERE id=?", (store.now(), summary, run_id))
        store.event("done", f"Run #{run_id} finished: {summary}", run_id)
        return run_id
    finally:
        _run_lock.release()


def scheduler(interval_min):
    def loop():
        import time
        while True:
            time.sleep(interval_min * 60)
            try:
                run_cycle("scheduled")
            except Exception as e:
                store.event("error", f"Scheduled run failed: {e}")
    threading.Thread(target=loop, daemon=True).start()
