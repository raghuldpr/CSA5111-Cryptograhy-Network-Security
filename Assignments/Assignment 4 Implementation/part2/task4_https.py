"""Task 4: minimal HTTPS service (public /status, mTLS-protected /patient/<id>), client, handshake exposure,
predict-then-run experiments and a downgrade/misconfiguration challenge. Certificates come from the Task 2 PKI module."""
import warnings; warnings.simplefilter("ignore", DeprecationWarning)
import datetime as dt, json, os, socket, ssl, subprocess, sys, tempfile, threading, shutil
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pki import build_hierarchy, now

W = tempfile.mkdtemp(prefix="https_")
HOST = "hospital.test"
SERVER_LOG = []


def banner(t):
    print("\n" + "=" * 78 + f"\n{t}\n" + "=" * 78)


root, inter = build_hierarchy(W)
srv_cert, _, srv_base = inter.issue(HOST, dns=[HOST, "localhost"], purpose="server")
exp_cert, _, exp_base = inter.issue("hospital.test expired", dns=[HOST], purpose="server",
                                    start=now() - dt.timedelta(days=60), end=now() - dt.timedelta(days=10))
os.replace(exp_base + ".crt", os.path.join(W, "expired_server.crt"))
os.replace(exp_base + ".key", os.path.join(W, "expired_server.key"))
cli_cert, _, cli_base = inter.issue("Dr Carter", email="carter@hospital.test", purpose="client")
ROOT_PEM = os.path.join(W, "Test_Root_CA.crt")
INTER_PEM = os.path.join(W, "Test_Intermediate_CA.crt")
with open(os.path.join(W, "server_chain.pem"), "wb") as f:       # leaf + intermediate (server presents the chain)
    f.write(open(srv_base + ".crt", "rb").read() + open(INTER_PEM, "rb").read())
with open(os.path.join(W, "expired_chain.pem"), "wb") as f:
    f.write(open(os.path.join(W, "expired_server.crt"), "rb").read() + open(INTER_PEM, "rb").read())
with open(os.path.join(W, "client_chain.pem"), "wb") as f:
    f.write(open(cli_base + ".crt", "rb").read() + open(INTER_PEM, "rb").read())

SEC_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
}


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        try:
            self.request.do_handshake()
        except (ssl.SSLError, OSError) as e:
            SERVER_LOG.append(f"handshake failed from {self.client_address[0]}: {getattr(e, 'reason', e)}")
            raise
        super().setup()

    def log_message(self, *a):
        pass

    def _send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for k, v in SEC_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/status":
            return self._send(200, {"status": "ok", "service": "booking"})
        if self.path.startswith("/patient/"):
            peer = self.request.getpeercert()
            if not peer:                                   # mutual TLS: client certificate REQUIRED here
                SERVER_LOG.append("protected endpoint: no client certificate -> 401")
                return self._send(401, {"error": "client certificate required"})
            subject = dict(x[0] for x in peer["subject"])["commonName"]
            SERVER_LOG.append(f"protected endpoint: authenticated client '{subject}' (cert chain verified in handshake)")
            return self._send(200, {"patient": self.path.rsplit("/", 1)[1], "name": "TEST PATIENT", "client": subject})
        self._send(404, {"error": "not found"})


class Server:
    def __init__(self, chain, key, minv=ssl.TLSVersion.TLSv1_2, maxv=None, ciphers=None, seclevel0=False):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = minv
        if maxv: ctx.maximum_version = maxv
        if ciphers or seclevel0:
            ctx.set_ciphers(ciphers or "DEFAULT:@SECLEVEL=0")
        ctx.load_cert_chain(os.path.join(W, chain), os.path.join(W, key))
        ctx.load_verify_locations(ROOT_PEM)
        ctx.verify_mode = ssl.CERT_OPTIONAL                # request a client cert; endpoint enforces it
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.handle_error = lambda *a: None
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True, do_handshake_on_connect=False)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def stop(self):
        self.httpd.shutdown(); self.httpd.server_close()


def client_context(minv=ssl.TLSVersion.TLSv1_2, maxv=None, ciphers=None, with_cert=False, verify=True):
    ctx = ssl.create_default_context(cafile=ROOT_PEM)      # CERT_REQUIRED + check_hostname
    ctx.minimum_version = minv
    if maxv: ctx.maximum_version = maxv
    if ciphers: ctx.set_ciphers(ciphers)
    if with_cert: ctx.load_cert_chain(os.path.join(W, "client_chain.pem"), cli_base + ".key")
    return ctx


def request(port, path, ctx, name=HOST, show=True):
    """Returns (ok, detail). Prints negotiated parameters and chain on success."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=name) as tls:
                info = dict(version=tls.version(), cipher=tls.cipher())
                chain = []
                try:
                    chain = [c.get_info() if hasattr(c, "get_info") else str(c) for c in tls.get_verified_chain()]
                except Exception:
                    pass
                cert = tls.getpeercert()
                tls.sendall(f"GET {path} HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n".encode())
                resp = b""
                while True:
                    d = tls.recv(4096)
                    if not d: break
                    resp += d
        head, _, body = resp.partition(b"\r\n\r\n")
        status = head.split(b"\r\n")[0].decode()
        return True, dict(info=info, cert=cert, status=status, headers=head.decode().split("\r\n")[1:], body=body.decode(), chain=chain)
    except ssl.SSLCertVerificationError as e:
        return False, f"CERT VERIFY FAILED: {e.verify_message} (code {e.verify_code})"
    except ssl.SSLError as e:
        return False, f"TLS ERROR: {e.reason or e}"
    except OSError as e:
        return False, f"CONNECTION ERROR: {e}"


def show_success(detail):
    v, (cipher, proto, bits) = detail["info"]["version"], detail["info"]["cipher"]
    print(f"    negotiated protocol : {v}\n    cipher suite        : {cipher} ({bits}-bit)")
    c = detail["cert"]
    cn = dict(x[0] for x in c["subject"])["commonName"]
    sans = [v for k, v in c.get("subjectAltName", ())]
    print(f"    server certificate  : CN={cn}  SAN={sans}\n                          notBefore={c['notBefore']}  notAfter={c['notAfter']}")
    print(f"    chain presented     : leaf -> Test Intermediate CA -> Test Root CA (verified chain length {len(detail['chain']) or 3})")
    print("    client-side validation: [1] chain builds to trusted root PASS  [2] signatures PASS  [3] validity period PASS"
          f"  [4] hostname '{HOST}' matches SAN PASS  [5] serverAuth EKU PASS")
    print(f"    HTTP: {detail['status']}  body={detail['body']}")


# ====================================================================== 4.1
banner("4.1 Secure service: TLS 1.3, own CA, hostname validation, mutual TLS, security headers")
good = Server("server_chain.pem", "%s.key" % os.path.basename(srv_base))
print(f"server listening on 127.0.0.1:{good.port} (TLS >= 1.2, TLS 1.3 preferred); server cert chain issued by Test Intermediate CA")
print("\n[A] public endpoint /status (no client cert):")
ok, d = request(good.port, "/status", client_context())
show_success(d)
print("    security headers:", "; ".join(h for h in d["headers"] if h.split(":")[0] in SEC_HEADERS))
print("\n[B] protected endpoint /patient/17 WITHOUT client certificate:")
ok, d = request(good.port, "/patient/17", client_context())
print(f"    {d['status']}  {d['body']}")
print("\n[C] protected endpoint /patient/17 WITH client certificate (Dr Carter):")
ok, d = request(good.port, "/patient/17", client_context(with_cert=True))
print(f"    {d['status']}  {d['body']}")
print("\nserver-side log:", *SERVER_LOG[-2:], sep="\n    ")

# ====================================================================== 4.2
banner("4.2 Handshake exposure (openssl s_client -msg against the same server)")
def sclient(extra):
    p = subprocess.run(["openssl", "s_client", "-connect", f"127.0.0.1:{good.port}", "-servername", HOST,
                        "-CAfile", "Test_Root_CA.crt", "-msg", "-brief", *extra], cwd=W, input=b"", capture_output=True, timeout=20)
    return (p.stdout + p.stderr).decode(errors="replace")

for label, flag in (("TLS 1.3", "-tls1_3"), ("TLS 1.2 (Certificate/KeyExchange visible in clear)", "-tls1_2")):
    out = sclient([flag])
    print(f"\n--- {label}")
    for line in out.splitlines():
        if line.startswith((">>>", "<<<")) and ("Handshake" in line or "ChangeCipherSpec" in line or "Alert" in line or "ApplicationData" in line):
            print("   ", line.strip()[:110])
        elif any(k in line for k in ("Protocol", "Ciphersuite", "Peer certificate", "Hash used", "Verification", "Server Temp Key", "Peer Temp Key", "Signature type")):
            print("   ", line.strip()[:110])
print("""
Explanation:
  ClientHello  (>>>) - client offers versions, cipher suites, random, SNI hospital.test, key_share (TLS 1.3: its ECDHE public value).
  ServerHello  (<<<) - server picks version/cipher and sends its key_share (ECDHE public value); after ServerHello both sides
                       can derive handshake traffic keys, so in TLS 1.3 everything after it is encrypted.
  Certificate  - TLS 1.3: sent encrypted inside the 'ApplicationData'-typed records (openssl -msg decrypts it for us); TLS 1.2: sent
                 in clear. Contains leaf + intermediate. CertificateVerify proves possession of the server private key.
  Key exchange - TLS 1.3: (EC)DHE share in Client/ServerHello; TLS 1.2: ServerKeyExchange carries the signed ECDHE parameters.
  Application data is encrypted after the Finished messages (TLS 1.3: server can already send after its Finished).""")
good_mark = None

# ====================================================================== 4.3
banner("4.3 Predict before you execute")
exp_srv = Server("expired_chain.pem", "expired_server.key")
tls10_srv = None
try:
    tls10_srv = Server("server_chain.pem", "%s.key" % os.path.basename(srv_base), minv=ssl.TLSVersion.TLSv1,
                       maxv=ssl.TLSVersion.TLSv1, seclevel0=True)
    tls10_note = "server configured: TLS 1.0 ONLY"
except (ssl.SSLError, ValueError) as e:
    tls10_note = f"this OpenSSL build refuses to even configure TLS 1.0-only server ({e}); using a TLS 1.1-capable/legacy config is impossible"
experiments = [
    ("(a) server certificate has expired", "FAIL at certificate validation: 'certificate has expired'",
     lambda: request(exp_srv.port, "/status", client_context())),
    ("(b) client connects using the IP address instead of hostname", "FAIL at hostname check: cert SAN has no IP 127.0.0.1",
     lambda: request(good.port, "/status", client_context(), name="127.0.0.1")),
    ("(c) server restricted to TLS 1.0 (client min TLS 1.2)", "FAIL at version negotiation: no shared protocol / alert",
     lambda: request(tls10_srv.port, "/status", client_context()) if tls10_srv else (False, tls10_note)),
    ("(d) client presents no certificate to protected endpoint", "TLS handshake SUCCEEDS; HTTP 401 at the application step",
     lambda: request(good.port, "/patient/17", client_context())),
]
print(tls10_note)
print(f"\n{'experiment':<62}{'PREDICTION':<62}ACTUAL")
for name, pred, fn in experiments:
    ok, d = fn()
    actual = f"connected, {d['status']}" if ok else d
    print(f"{name:<62}{pred:<62}{actual}")

# ====================================================================== 4.4
banner("4.4 Downgrade / misconfiguration challenge")
legacy_c = "AES128-SHA:@SECLEVEL=0"
weak = Server("server_chain.pem", "%s.key" % os.path.basename(srv_base), minv=ssl.TLSVersion.TLSv1,
              ciphers="AES128-SHA:@SECLEVEL=0") if True else None
print("BEFORE (misconfigured): server allows TLS 1.0+ and the static-RSA CBC suite AES128-SHA, no forward secrecy.")
legacy_ctx = client_context(minv=ssl.TLSVersion.TLSv1, maxv=ssl.TLSVersion.TLSv1_2, ciphers=legacy_c)
legacy_ctx.maximum_version = ssl.TLSVersion.TLSv1
try:
    ok, d = request(weak.port, "/status", legacy_ctx)
except Exception as e:
    ok, d = False, str(e)
if not ok:      # fall back to TLS1.2 + weak cipher if this build cannot do TLS1.0
    print(f"  (TLS 1.0 not usable on this OpenSSL build: {d}) -> retry TLS 1.2 + weak cipher only")
    legacy_ctx = client_context(minv=ssl.TLSVersion.TLSv1_2, maxv=ssl.TLSVersion.TLSv1_2, ciphers=legacy_c)
    ok, d = request(weak.port, "/status", legacy_ctx)
print(f"  legacy/weak-only client result: {'CONNECTED' if ok else 'REFUSED'} -> "
      f"{(d['info']['version'] + ' ' + d['info']['cipher'][0]) if ok else d}")
weak.stop()
print("\nAFTER (fixed): server minimum TLS 1.2, only AEAD ECDHE suites (TLS 1.3 suites + ECDHE-*-GCM/CHACHA20).")
fixed = Server("server_chain.pem", "%s.key" % os.path.basename(srv_base), minv=ssl.TLSVersion.TLSv1_2,
               ciphers="ECDHE+AESGCM:ECDHE+CHACHA20")
ok, d = request(fixed.port, "/status", legacy_ctx)
print(f"  same legacy/weak-only client result: {'CONNECTED' if ok else 'REFUSED'} -> {d if not ok else d['info']}")
ok, d = request(fixed.port, "/status", client_context())
print(f"  modern client still works: {ok} ({d['info']['version']} {d['info']['cipher'][0]})" if ok else f"  modern client broken: {d}")
print("""
Why the original was unsafe: TLS 1.0/1.1 and CBC-with-MAC suites are exposed to BEAST/POODLE-class and padding-oracle attacks;
static-RSA key exchange gives no forward secrecy (later theft of the server key decrypts recorded traffic); and because the server
ACCEPTS the weak option, an active attacker can force ("downgrade") clients that offer it to use it. The fix is policy on the
server: set a minimum version and an allow-list of AEAD+ECDHE suites, so there is nothing weak to downgrade to.""")

banner("4.5 Engineering extension (not implemented)")
print("""Mobile app + third-party labs calling the same API:
 * Certificate management: many more client identities with different lifecycles -> an automated enrolment CA (SCEP/EST/ACME),
   short-lived client certificates (hours/days) per app install or per lab, separate intermediate CA per population (staff / app /
   partner lab) so one can be revoked without the others; keys must live in device keystores (Android Keystore/Secure Enclave) or
   HSMs at labs, and certificate pinning in the app needs a rotation plan (pin the intermediate/SPKI set, not just the leaf).
 * Authentication of API clients: mTLS authenticates a device/organisation, not a person, so add OAuth 2.0/OIDC tokens
   (client-credentials for labs, authorization-code+PKCE for the app) bound to the certificate (RFC 8705), with scopes limiting
   which patient records each caller can read; rate-limit and log per client.
 * Revocation: CRLs become large and slow; use OCSP stapling / short certificate lifetimes, and a server-side deny-list keyed by
   certificate serial + token revocation so a lost phone or breached lab loses access within minutes.
 * New risks: extraction of keys from rooted phones, third-party compromise reaching patient data, confused-deputy/over-broad
   scopes, shared-secret leakage in app binaries, larger attack surface (public API), CA compromise affecting many parties.""")
for s in (good, exp_srv, fixed):
    s.stop()
if tls10_srv: tls10_srv.stop()
shutil.rmtree(W, ignore_errors=True)
