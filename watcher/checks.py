"""The agent's tools: read a site's SSL certificate, and look up a domain's
registration expiry through RDAP (the official successor to WHOIS)."""
import socket
import ssl
from datetime import datetime, timezone

import requests
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

from . import lab

MULTI_PART_SUFFIXES = {"co.in", "org.in", "net.in", "ac.in", "gov.in", "edu.in", "res.in", "firm.in", "gen.in", "ind.in",
                       "co.uk", "org.uk", "ac.uk", "com.au", "net.au", "org.au", "co.jp", "com.br", "com.sg", "co.nz"}


class CheckFailed(Exception):
    pass


def registrable_domain(host):
    """github.com for api.github.com; iitm.ac.in for www.iitm.ac.in."""
    parts = host.lower().split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _name(name, oid):
    try:
        return name.get_attributes_for_oid(oid)[0].value
    except Exception:
        return ""


def tls_check(host, port=443, connect_addr=None, timeout=8):
    """Connect, read the certificate the server presents for this host name (SNI), and return its facts."""
    addr = connect_addr or host
    if lab.is_lab_host(host):
        addr, port = "127.0.0.1", lab.PORT
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we want the facts even for broken or expired certificates
    try:
        with socket.create_connection((addr, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                der = s.getpeercert(binary_form=True)
    except socket.gaierror:
        raise CheckFailed(f"DNS lookup failed: {addr} has no address, so its certificate could not be read")
    except (socket.timeout, TimeoutError):
        raise CheckFailed(f"Timed out connecting to {addr}:{port}")
    except ConnectionRefusedError:
        raise CheckFailed(f"Connection refused by {addr}:{port} (no HTTPS service)")
    except Exception as e:
        raise CheckFailed(f"Could not read certificate from {addr}:{port} — {type(e).__name__}: {e}")
    cert = x509.load_der_x509_certificate(der)
    trusted, trust_error = True, ""
    if not lab.is_lab_host(host):
        try:
            v = ssl.create_default_context()
            with socket.create_connection((addr, port), timeout=timeout) as raw:
                with v.wrap_socket(raw, server_hostname=host):
                    pass
        except ssl.SSLCertVerificationError as e:
            trusted, trust_error = False, e.verify_message or str(e)
        except Exception as e:
            trusted, trust_error = None, str(e)
    else:
        trusted, trust_error = None, "lab certificate (self-signed test fixture)"
    try:
        sans = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
    except Exception:
        sans = []
    expires = cert.not_valid_after_utc
    return {
        "expires_at": expires.isoformat(),
        "days_left": round((expires - datetime.now(timezone.utc)).total_seconds() / 86400, 1),
        "serial": format(cert.serial_number, "x"),
        "issuer": _name(cert.issuer, NameOID.ORGANIZATION_NAME) or _name(cert.issuer, NameOID.COMMON_NAME),
        "subject": _name(cert.subject, NameOID.COMMON_NAME),
        "source": f"TLS handshake {addr}:{port} (SNI {host})",
        "evidence": {"not_before": cert.not_valid_before_utc.isoformat(), "not_after": expires.isoformat(),
                     "sans": sans[:20], "trusted": trusted, "trust_error": trust_error,
                     "covers_host": any(_matches(host, s) for s in sans) if sans else None},
    }


def _matches(host, pattern):
    if pattern.startswith("*."):
        return host.count(".") == pattern.count(".") and host.endswith(pattern[1:])
    return host == pattern


def rdap_check(domain, timeout=12):
    """Registration expiry from RDAP. Raises CheckFailed when the lookup service fails."""
    url = f"https://rdap.org/domain/{domain}"
    if lab.lookup_outage():
        raise CheckFailed(f"Lookup service unavailable: {url} did not respond (simulated outage for test case TC3)")
    try:
        r = requests.get(url, timeout=timeout, headers={"Accept": "application/rdap+json"})
    except Exception as e:
        raise CheckFailed(f"Lookup service error for {domain}: {type(e).__name__}: {e}")
    if r.status_code != 200:
        raise CheckFailed(f"Lookup service returned HTTP {r.status_code} for {domain}")
    data = r.json()
    exp = next((e["eventDate"] for e in data.get("events", []) if e.get("eventAction") == "expiration"), None)
    if not exp:
        raise CheckFailed(f"Lookup for {domain} returned no expiration date (registry does not publish it)")
    expires = datetime.fromisoformat(exp.replace("Z", "+00:00"))
    registrar = ""
    for ent in data.get("entities", []):
        if "registrar" in ent.get("roles", []):
            try:
                registrar = next(v[3] for v in ent["vcardArray"][1] if v[0] == "fn")
            except Exception:
                registrar = ent.get("handle", "")
    return {
        "expires_at": expires.isoformat(),
        "days_left": round((expires - datetime.now(timezone.utc)).total_seconds() / 86400, 1),
        "serial": "", "issuer": registrar, "subject": domain,
        "source": r.url,
        "evidence": {"rdap_url": r.url, "registrar": registrar, "status": data.get("status", [])[:6],
                     "events": [(e.get("eventAction"), e.get("eventDate")) for e in data.get("events", [])][:6]},
    }
