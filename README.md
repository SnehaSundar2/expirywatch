# ExpiryWatch — an SSL & domain expiry watcher agent

**Ziro Agentic AI Hackathon 2026. Track: Developer & Enterprise AI. Assigned problem: SSL & Domain Expiry Watcher.**

## Problem

When an SSL certificate expires, browsers show "Your connection is not private" and customers leave. When a domain registration lapses, the whole site and its email go dark. Both are entirely preventable, yet they still cause outages. Expiry dates sit in different places (certificates on the servers, registrations at registrars), nobody owns the reminder, and renewal steps are forgotten.

**Goal: alert the team before a certificate or domain expires, open a renewal ticket with human approval, and confirm the renewal actually happened.**

## What the agent does

| Brief step | ExpiryWatch |
|---|---|
| **Collect the details**: domains list | Add domains in the UI. Each one is validated (domain syntax, port) and gets a stable ID such as `github-com`. Every host becomes a *certificate item*; every registrable domain (e.g. `iitm.ac.in` for `www.iitm.ac.in`) becomes a *registration item*. |
| **Plan the next steps** | Each run starts with a plan. The AI planner (Gemini, Claude or OpenAI) decides what to check and why: never-checked, alerting, near-expiry and unverified items first; recently checked healthy items can be skipped. **Guard rail in code:** the planner can never skip a risky or unverified item. Without an AI key, a rule-based planner does the same job. |
| **Find the information**: domain lookup and sites | **Tool 1:** a live TLS handshake with SNI reads the certificate each site actually serves: expiry, serial, issuer, the domains it covers, and whether browsers trust it. **Tool 2:** an **RDAP** lookup (the official successor to WHOIS) gets the registration expiry and registrar. Each result stores its source URL and retrieval time. |
| **Decision rule**: days to expiry | Explicit comparisons. Certificate: ≤30 days warning, ≤14 critical, <0 expired. Domain: ≤60 warning, ≤30 critical. If evidence is missing, the item becomes **UNCHECKED**: no alert is raised, none is cleared, and no date is guessed. |
| **Take action**: renewal ticket, *human approval required* | For critical or expired items the agent **proposes** a ticket. The AI writes it with renewal steps that fit the issuer or registrar. A person sees the destination, title and body, then approves or rejects. Only an approval opens it, either on the built-in board or as a **GitHub Issue**. The approved version is stored. An **idempotency key** (item + certificate serial or expiry date) prevents duplicates on retries or double clicks. |
| **Produce**: expiry calendar | A calendar on the dashboard groups everything by month, with status colours and "last known" dates for unchecked items. It can be exported as an `.ics` file for Google or Outlook calendar, with reminders 14 days before. |
| **Check it works**: rechecks after renewal | A separate verification step runs on later checks. A ticket closes only when a recheck shows a **new certificate serial or new expiry date** and a healthy status. Otherwise it stays open with "not renewed yet". If something was renewed before anyone approved the proposal, the proposal is withdrawn. |

Alerts are shown on the dashboard. They can also be pushed to Slack, Discord or Google Chat (`ALERT_WEBHOOK_URL`). Checks run on a schedule (`CHECK_INTERVAL_MIN`) and on demand.

## Architecture

```
Domains list (validated, stable IDs)
        │
        ▼
┌──────────────────────── Agent run (watcher/agent.py) ────────────────────────┐
│ 1 PLAN    AI planner → check/skip each item with a reason                    │
│           guard rail: risky / unverified items are always checked            │
│ 2 GATHER  tools: TLS handshake (certificate)   RDAP lookup (registration)    │
│           failure → item marked UNCHECKED (one retry for network blips)      │
│ 3 DECIDE  days-to-expiry rules → ok / warning / critical / expired           │
│           alerts raised / cleared only on real evidence                      │
│ 4 ACT     propose renewal ticket (AI-written) ──► HUMAN APPROVAL ──► open    │
│           idempotency key stops duplicate tickets                            │
│ 5 VERIFY  recheck after renewal: new serial / expiry? → resolve ticket       │
└──────────────────────────────────────────────────────────────────────────────┘
        │                                   │
   SQLite (checks + evidence, alerts,   Dashboard: approvals, expiry calendar,
   tickets + approval history, runs)    evidence, agent log, test-case page, .ics
```

| File | Role |
|---|---|
| `watcher/agent.py` | Plan → gather → decide → act → verify loop, approval, idempotency |
| `watcher/checks.py` | Tools: TLS certificate reader, RDAP domain lookup, registrable-domain logic (handles `.co.in`, `.ac.in` and similar) |
| `watcher/llm.py` | AI client for Gemini, Claude or OpenAI, whichever key is set |
| `watcher/lab.py` | Test lab: local HTTPS server with synthetic certificates per host (SNI), renewal, and a lookup-outage switch |
| `watcher/testcases.py` | The 4 official test cases, recorded with input, expected, actual and evidence |
| `watcher/store.py` | SQLite storage and input validation |
| `app.py`, `templates/` | Flask dashboard and API |

## Official test cases

Run them on the **Official test cases** page. Each result is stored with its input, expected result, actual result, raw evidence and timestamp.

| # | Scenario | Expected | How it is run | Result |
|---|---|---|---|---|
| TC1 | Certificate expires in 10 days | Alert and renewal ticket | The lab serves `shop.lab.test` with a certificate that expires in 10 days | ✅ CRITICAL, alert raised, ticket proposed and waiting for approval |
| TC2 | Certificate renewed | Alert cleared after recheck | The lab certificate is renewed (new serial, 90 days); the agent rechecks | ✅ New serial detected, alert cleared, approved ticket marked **resolved (verified)** |
| TC3 | Lookup service fails | Domain marked unchecked | The RDAP lookup service is made unavailable for `github.com` | ✅ UNCHECKED with the reason; no alert raised, no date guessed |
| TC4 | Subdomain with its own certificate | Tracked separately | `shop.lab.test` and `api.shop.lab.test` each serve their own certificate | ✅ Two items with different serials and expiries, and separate alerts and tickets |

Real public domains are also watched: `github.com`, `google.com`, `www.iitm.ac.in`, and `expired.badssl.com` (a certificate that is deliberately expired).

## Run it

```
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000. On Windows you can double-click `run.bat` instead. To use the AI planner, copy `.env.example` to `.env` and add a key. Free hosting on Render works through `render.yaml`.

## Safety

- The only outward action is opening a ticket, and it happens only after a person approves it.
- The agent reads public certificates and public RDAP records only. It never logs in to registrars or CAs, never pays and never renews anything by itself.
- Uncertain evidence is labelled as uncertain and never presented as a result.
