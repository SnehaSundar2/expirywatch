"""SQLite storage: monitored domains, every check (with evidence), alerts,
renewal tickets (with approval history), agent runs, events and test runs."""
import json
import os
import re
import sqlite3
import threading
from datetime import datetime, timezone

DB_PATH = os.getenv("DB_PATH", os.path.join(os.path.dirname(os.path.dirname(__file__)), "expirywatch.db"))
_lock = threading.RLock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS domains (
  id TEXT PRIMARY KEY, host TEXT NOT NULL, port INTEGER NOT NULL DEFAULT 443,
  connect_addr TEXT, label TEXT, owner TEXT, created_at TEXT, enabled INTEGER DEFAULT 1,
  UNIQUE(host, port));
CREATE TABLE IF NOT EXISTS checks (
  id INTEGER PRIMARY KEY AUTOINCREMENT, item_key TEXT, domain_id TEXT, kind TEXT, run_id INTEGER,
  checked_at TEXT, status TEXT, expires_at TEXT, days_left REAL, serial TEXT, issuer TEXT, subject TEXT,
  source TEXT, evidence TEXT, error TEXT);
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT, item_key TEXT, domain_id TEXT, kind TEXT, state TEXT,
  severity TEXT, reason TEXT, opened_at TEXT, opened_check INTEGER, cleared_at TEXT, cleared_check INTEGER);
CREATE TABLE IF NOT EXISTS tickets (
  id INTEGER PRIMARY KEY AUTOINCREMENT, idem_key TEXT UNIQUE, item_key TEXT, domain_id TEXT, kind TEXT,
  state TEXT, destination TEXT, title TEXT, body TEXT, priority TEXT, created_at TEXT, check_id INTEGER,
  decided_at TEXT, decided_by TEXT, approved_snapshot TEXT, external_ref TEXT,
  verified_at TEXT, verify_note TEXT);
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, trigger TEXT, started_at TEXT, finished_at TEXT,
  planner TEXT, plan TEXT, summary TEXT);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, t TEXT, run_id INTEGER, kind TEXT, msg TEXT, item_key TEXT);
CREATE TABLE IF NOT EXISTS testruns (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tc TEXT, scenario TEXT, input TEXT, expected TEXT, actual TEXT,
  result TEXT, evidence TEXT, ran_at TEXT);
"""


def now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def conn():
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


def init():
    with _lock, conn() as c:
        c.executescript(SCHEMA)


def q(sql, args=(), one=False):
    with _lock, conn() as c:
        rows = [dict(r) for r in c.execute(sql, args).fetchall()]
    return (rows[0] if rows else None) if one else rows


def x(sql, args=()):
    with _lock, conn() as c:
        cur = c.execute(sql, args)
        return cur.lastrowid


def slug(host, port):
    s = re.sub(r"[^a-z0-9]+", "-", host.lower()).strip("-")
    return s if int(port) == 443 else f"{s}-{port}"


HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def validate_host(host):
    host = (host or "").strip().lower()
    host = re.sub(r"^https?://", "", host).split("/")[0].split(":")[0]
    if not HOST_RE.match(host):
        raise ValueError(f"'{host}' is not a valid domain name")
    return host


def add_domain(host, port=443, label="", owner="DevOps", connect_addr=None):
    host = validate_host(host)
    port = int(port or 443)
    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535")
    did = slug(host, port)
    if q("SELECT id FROM domains WHERE id=?", (did,), one=True):
        return did
    x("INSERT INTO domains (id, host, port, connect_addr, label, owner, created_at) VALUES (?,?,?,?,?,?,?)",
      (did, host, port, connect_addr, label, owner, now()))
    return did


def event(kind, msg, run_id=None, item_key=None):
    x("INSERT INTO events (t, run_id, kind, msg, item_key) VALUES (?,?,?,?,?)", (now(), run_id, kind, msg, item_key))


def latest_checks():
    """Most recent check for every item."""
    return q("""SELECT c.* FROM checks c JOIN (SELECT item_key, MAX(id) mid FROM checks GROUP BY item_key) m
                ON c.id = m.mid ORDER BY c.days_left IS NULL, c.days_left""")


def last_good(item_key):
    return q("SELECT * FROM checks WHERE item_key=? AND status!='unchecked' ORDER BY id DESC LIMIT 1", (item_key,), one=True)


def dumps(o):
    return json.dumps(o, ensure_ascii=False, default=str)
