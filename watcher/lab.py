"""Test lab: a small local HTTPS server that presents synthetic certificates
(one per host name, chosen by SNI) so the official test cases can be run on
demand: a certificate that expires in 10 days, a renewal, and a subdomain with
its own certificate. Also a switch that simulates the lookup service failing."""
import os
import socket
import ssl
import tempfile
import threading
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

PORT = int(os.getenv("LAB_PORT", "8443"))
LAB_SUFFIX = ".lab.test"
DIR = os.path.join(tempfile.gettempdir(), "expirywatch-lab")
_contexts = {}
_state = {"outage": False, "started": False}
_lock = threading.Lock()


def is_lab_host(host):
    return host.endswith(LAB_SUFFIX)


def lookup_outage():
    return _state["outage"]


def set_lookup_outage(on):
    _state["outage"] = bool(on)


def issue(host, days):
    """Create a fresh self-signed certificate for host that expires in `days` days."""
    os.makedirs(DIR, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ExpiryWatch Test Lab CA")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .sign(key, hashes.SHA256()))
    cpath, kpath = os.path.join(DIR, host + ".crt"), os.path.join(DIR, host + ".key")
    with open(cpath, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(kpath, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cpath, kpath)
    with _lock:
        _contexts[host] = ctx
    return format(cert.serial_number, "x")


def _sni(sock, server_name, ctx):
    with _lock:
        c = _contexts.get(server_name or "")
    if c:
        sock.context = c


def _serve():
    default = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    first = next(iter(_contexts))
    default.load_cert_chain(os.path.join(DIR, first + ".crt"), os.path.join(DIR, first + ".key"))
    default.sni_callback = _sni
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", PORT))
    srv.listen(20)
    while True:
        client, _ = srv.accept()
        threading.Thread(target=_handle, args=(client, default), daemon=True).start()


def _handle(client, ctx):
    try:
        client.settimeout(5)
        with ctx.wrap_socket(client, server_side=True) as s:
            s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
    except Exception:
        pass


SCENARIO = {"shop.lab.test": 10, "api.shop.lab.test": 200}


def reset():
    """Put the lab back to the starting scenario."""
    for host, days in SCENARIO.items():
        issue(host, days)
    set_lookup_outage(False)


def renew(host, days=90):
    return issue(host, days)


def start():
    if _state["started"]:
        return
    reset()
    threading.Thread(target=_serve, daemon=True).start()
    _state["started"] = True
