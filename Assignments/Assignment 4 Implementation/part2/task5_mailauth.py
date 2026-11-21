"""Task 5: SPF + DKIM + DMARC checkers over a simulated DNS zone (local JSON file) with evidence traces."""
import base64, hashlib, ipaddress, json, os, re, sys, tempfile
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature

HERE = os.path.dirname(os.path.abspath(__file__))


def banner(t):
    print("\n" + "=" * 78 + f"\n{t}\n" + "=" * 78)


# ------------------------------------------------------------------ simulated DNS
def make_keypair():
    k = rsa.generate_private_key(65537, 2048)
    pub = base64.b64encode(k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
    return k, pub


KEYS = {d: make_keypair() for d in ("example.org", "attacker.test", "lists.example.net")}
ZONE = {                                      # what an administrator would publish
    "example.org": {"TXT": ["v=spf1 ip4:192.0.2.10 ip4:192.0.2.0/28 -all"]},
    "_dmarc.example.org": {"TXT": ["v=DMARC1; p=reject; adkim=r; aspf=r"]},
    "s1._domainkey.example.org": {"TXT": [f"v=DKIM1; k=rsa; p={KEYS['example.org'][1]}"]},
    "attacker.test": {"TXT": ["v=spf1 ip4:203.0.113.66 -all"]},
    "s1._domainkey.attacker.test": {"TXT": [f"v=DKIM1; k=rsa; p={KEYS['attacker.test'][1]}"]},
    "_dmarc.attacker.test": {"TXT": ["v=DMARC1; p=none"]},
    "lists.example.net": {"TXT": ["v=spf1 ip4:198.51.100.25 -all"]},
    "s1._domainkey.lists.example.net": {"TXT": [f"v=DKIM1; k=rsa; p={KEYS['lists.example.net'][1]}"]},
}
ZONE_FILE = os.path.join(tempfile.gettempdir(), "task5_zone.json")
json.dump(ZONE, open(ZONE_FILE, "w"), indent=1)


def dns_txt(name):
    zone = json.load(open(ZONE_FILE))
    return zone.get(name, {}).get("TXT", [])


# ------------------------------------------------------------------------- SPF
def spf_check(client_ip, mail_from_domain, depth=0, trace=None):
    """Authenticates: the connecting IP against the policy of the ENVELOPE (MAIL FROM) domain."""
    trace = trace if trace is not None else []
    recs = [r for r in dns_txt(mail_from_domain) if r.startswith("v=spf1")]
    if not recs:
        trace.append(f"no SPF record for {mail_from_domain}")
        return "none", trace
    trace.append(f"DNS TXT {mail_from_domain}: {recs[0]}")
    for term in recs[0].split()[1:]:
        q = "+"
        if term[0] in "+-~?":
            q, term = term[0], term[1:]
        hit = False
        if term.startswith("ip4:"):
            net = ipaddress.ip_network(term[4:], strict=False)
            hit = ipaddress.ip_address(client_ip) in net
            trace.append(f"  mechanism ip4:{net}: client {client_ip} {'MATCH' if hit else 'no match'}")
        elif term.startswith("include:") and depth < 5:
            r, _ = spf_check(client_ip, term[8:], depth + 1, trace)
            hit = r == "pass"
        elif term == "all":
            hit = True
            trace.append("  mechanism all: reached")
        if hit:
            res = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}[q]
            return res, trace
    return "neutral", trace


# ------------------------------------------------------------------------ DKIM
def canon_header(name, value):
    return f"{name.lower()}:{re.sub(r'[ \t]+', ' ', value.replace(chr(13), '').replace(chr(10), '')).strip()}\r\n"


def canon_body(body):
    lines = [re.sub(r"[ \t]+", " ", l).rstrip(" ") for l in body.replace("\r\n", "\n").split("\n")]
    while lines and lines[-1] == "":
        lines.pop()
    return ("\r\n".join(lines) + "\r\n") if lines else "\r\n"


SIGNED = ["from", "to", "subject", "date"]


def dkim_sign(headers, body, domain, selector="s1"):
    bh = base64.b64encode(hashlib.sha256(canon_body(body).encode()).digest()).decode()
    hdrs = {k.lower(): v for k, v in headers}
    tmpl = f"v=1; a=rsa-sha256; c=relaxed/relaxed; d={domain}; s={selector}; h={':'.join(SIGNED)}; bh={bh}; b="
    data = "".join(canon_header(h, hdrs[h]) for h in SIGNED if h in hdrs) + canon_header("dkim-signature", tmpl).rstrip("\r\n")
    sig = KEYS[domain][0].sign(data.encode(), padding.PKCS1v15(), hashes.SHA256())
    return tmpl + base64.b64encode(sig).decode()


def dkim_verify(headers, body):
    """Authenticates: the SIGNING domain (d=) and that signed headers/body are unchanged since signing."""
    trace = []
    sigs = [v for k, v in headers if k.lower() == "dkim-signature"]
    if not sigs:
        return "none", None, ["no DKIM-Signature header"]
    sig = sigs[0]
    tags = dict(t.strip().split("=", 1) for t in sig.split(";") if "=" in t)
    d, s = tags["d"], tags["s"]
    trace.append(f"DKIM-Signature: d={d} s={s} h={tags['h']} (signing domain = {d})")
    recs = dns_txt(f"{s}._domainkey.{d}")
    if not recs:
        return "permerror", d, trace + [f"no key record at {s}._domainkey.{d}"]
    pub = serialization.load_der_public_key(base64.b64decode(dict(x.strip().split("=", 1) for x in recs[0].split(";") if "=" in x)["p"]))
    trace.append(f"DNS TXT {s}._domainkey.{d}: public key found ({pub.key_size} bit)")
    bh = base64.b64encode(hashlib.sha256(canon_body(body).encode()).digest()).decode()
    if bh != tags["bh"]:
        return "fail", d, trace + [f"body hash mismatch: computed {bh[:12]}.. != signed {tags['bh'][:12]}.. (body changed after signing)"]
    trace.append(f"body hash matches ({bh[:12]}..)")
    hdrs = {k.lower(): v for k, v in headers}
    data = "".join(canon_header(h, hdrs[h]) for h in tags["h"].split(":") if h in hdrs)
    data += canon_header("dkim-signature", sig[:sig.rindex("b=") + 2]).rstrip("\r\n")
    try:
        pub.verify(base64.b64decode(tags["b"]), data.encode(), padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        return "fail", d, trace + ["signature over signed headers invalid (a signed header changed)"]
    return "pass", d, trace + ["RSA signature over canonicalised headers valid"]


# ----------------------------------------------------------------------- DMARC
def org_domain(d):
    return ".".join(d.lower().split(".")[-2:])       # simplification of the Public Suffix List


def aligned(a, b, mode):
    return a.lower() == b.lower() if mode == "s" else org_domain(a) == org_domain(b)


def dmarc_eval(from_domain, spf_res, spf_domain, dkim_res, dkim_domain):
    """Authenticates: that SPF or DKIM passed FOR A DOMAIN ALIGNED with the visible From domain."""
    trace = []
    recs = [r for r in dns_txt(f"_dmarc.{from_domain}") if r.startswith("v=DMARC1")]
    if not recs:
        return "none", "no policy -> deliver", [f"no _dmarc.{from_domain} record"]
    tags = dict(t.strip().split("=", 1) for t in recs[0].split(";") if "=" in t)
    trace.append(f"DNS TXT _dmarc.{from_domain}: {recs[0]}")
    aspf, adkim = tags.get("aspf", "r"), tags.get("adkim", "r")
    spf_al = spf_res == "pass" and aligned(spf_domain, from_domain, aspf)
    dkim_al = dkim_res == "pass" and dkim_domain and aligned(dkim_domain, from_domain, adkim)
    trace.append(f"SPF  : result={spf_res}, authenticated domain={spf_domain}, From={from_domain} -> aligned={spf_al}")
    trace.append(f"DKIM : result={dkim_res}, signing domain={dkim_domain}, From={from_domain} -> aligned={dkim_al}")
    ok = spf_al or dkim_al
    pol = tags.get("p", "none")
    action = "deliver" if ok else {"none": "deliver (monitor only)", "quarantine": "quarantine", "reject": "REJECT"}[pol]
    return ("pass" if ok else "fail"), action, trace


def evaluate(msg):
    spf_dom = msg["mail_from"].split("@")[1]
    spf_res, spf_trace = spf_check(msg["ip"], spf_dom)
    dk_res, dk_dom, dk_trace = dkim_verify(msg["headers"], msg["body"])
    from_dom = dict((k.lower(), v) for k, v in msg["headers"])["from"].split("@")[1].strip(">")
    dm_res, action, dm_trace = dmarc_eval(from_dom, spf_res, spf_dom, dk_res, dk_dom)
    return dict(spf=spf_res, spf_domain=spf_dom, dkim=dk_res, dkim_domain=dk_dom, dmarc=dm_res, action=action,
                trace=("SPF:", spf_trace, "DKIM:", dk_trace, "DMARC:", dm_trace), from_dom=from_dom)


# ------------------------------------------------------------------ test messages
def build(from_addr, mail_from, ip, sign_domain=None, body="Please approve invoice 1042.\r\n", subject="Invoice"):
    headers = [("From", from_addr), ("To", "bob@customer.example"), ("Subject", subject), ("Date", "Fri, 20 Nov 2026 10:00:00 +0000")]
    m = {"headers": headers, "body": body, "mail_from": mail_from, "ip": ip}
    if sign_domain:
        m["headers"] = [("DKIM-Signature", dkim_sign(headers, body, sign_domain))] + headers
    return m


banner("Simulated DNS zone published for the test domains (stored in %s)" % ZONE_FILE)
for name, rec in ZONE.items():
    txt = rec["TXT"][0]
    print(f"  {name:36s} TXT {txt[:78]}{'...' if len(txt) > 78 else ''}")

legit = build("alice@example.org", "alice@example.org", "192.0.2.10", "example.org")
spoof = build("ceo@example.org", "ceo@example.org", "203.0.113.66")
signed = build("alice@example.org", "alice@example.org", "192.0.2.10", "example.org", subject="Invoice")
# mailing list: modifies subject + body AFTER signing, relays from its own server, envelope sender is the list's
listmsg = {"headers": [(k, ("[staff] " + v) if k == "Subject" else v) for k, v in signed["headers"]],
           "body": signed["body"] + "-- \r\nYou are on the staff list.\r\n", "mail_from": "bounce@lists.example.net", "ip": "198.51.100.25"}
other_spf = build("ceo@example.org", "mallory@attacker.test", "203.0.113.66")                 # SPF passes for attacker.test
other_dkim = build("ceo@example.org", "mallory@attacker.test", "198.51.100.99", "attacker.test")  # DKIM d=attacker.test
fwd = dict(signed, mail_from="alice@example.org", ip="198.51.100.77")                          # forwarded unmodified
forward_envelope = dict(fwd, mail_from="fwd@lists.example.net")                                # forwarder rewrites envelope sender (SRS-like)
forward_envelope["ip"] = "198.51.100.25"

tests = [
    ("M1 legitimate (alice via own server, DKIM-signed)", legit, "SPF pass(aligned), DKIM pass(aligned) -> DMARC pass -> deliver"),
    ("M2 spoofed: From ceo@example.org from unauthorised IP, unsigned", spoof, "SPF fail, DKIM none -> DMARC fail -> REJECT"),
    ("M3 mailing list modified subject+footer after DKIM signing", listmsg, "SPF pass for lists.example.net but NOT aligned; DKIM fail (body/subject changed) -> DMARC fail -> REJECT (legit message lost!)"),
    ("M4 passes SPF for attacker.test but visible From is example.org", other_spf, "SPF pass (unaligned), DKIM none -> DMARC fail -> REJECT"),
    ("M5 attacker signs DKIM as attacker.test, From example.org", other_dkim, "SPF fail, DKIM pass (d=attacker.test, unaligned) -> DMARC fail -> REJECT"),
    ("M6 unmodified forward through relay (IP/envelope changed)", forward_envelope, "SPF pass for relay domain but unaligned; DKIM still pass+aligned -> DMARC pass -> deliver"),
]

banner("Predictions (made before running) and actual evidence")
results = []
for name, m, pred in tests:
    print(f"\n--- {name}\n    envelope MAIL FROM={m['mail_from']}  client IP={m['ip']}  visible From={dict(m['headers'])['From']}")
    print(f"    PREDICTION: {pred}")
    r = evaluate(m)
    results.append((name, r))
    for label, tr in ((r['trace'][0], r['trace'][1]), (r['trace'][2], r['trace'][3]), (r['trace'][4], r['trace'][5])):
        print(f"    {label}")
        for line in tr: print(f"      {line}")
    print(f"    ACTUAL: SPF={r['spf']}  DKIM={r['dkim']}  DMARC={r['dmarc']}  -> {r['action']}")

banner("Outcome table")
print(f"{'message':<62}{'SPF':<10}{'DKIM':<10}{'DMARC':<8}action")
for name, r in results:
    print(f"{name[:60]:<62}{r['spf']:<10}{r['dkim']:<10}{r['dmarc']:<8}{r['action']}")

print("""
What each mechanism authenticates (observed):
  SPF   - the ENVELOPE sender domain (MAIL FROM / HELO) vs the CONNECTING IP. It says nothing about the visible From (M4).
          DNS: TXT at the domain listing authorised IPs/includes.
  DKIM  - the SIGNING domain d= and that signed headers + body hash are unchanged. Not tied to the visible From (M5).
          DNS: TXT at selector._domainkey.domain with the public key. Signed: listed headers (h=) + canonical body hash.
  DMARC - ties the above to the visible From domain via ALIGNMENT and publishes the policy (none/quarantine/reject).
          DNS: TXT at _dmarc.<from-domain>.
Questions:
  * Can a message pass SPF or DKIM and still fail DMARC?  YES - M4 (SPF pass, unaligned) and M5 (DKIM pass, unaligned): an attacker
    can authenticate their OWN domain perfectly; only alignment with the visible From makes the check meaningful.
  * Can a legitimate message fail?  YES - M3: a mailing list changed the subject/body, breaking DKIM, and relays from its own IP so SPF
    is unaligned; with p=reject the genuine message is rejected. M6 shows the opposite: a relay that is not in the From domain's SPF leaves SPF unaligned but unmodified DKIM
    survives and DMARC still passes. Hence DKIM is the more forwarding-robust of the two.

Deployment analysis:
  A. Small company, one mail server: SPF listing one IP + DKIM on that server + DMARC p=quarantine -> reject is easy; few moving parts, so
     strict alignment is realistic. Forwarding by recipients is the main source of false positives (SPF breaks, DKIM saves).
  B. Large organisation with third-party senders (CRM, newsletter, ticketing): SPF record grows (10-lookup limit), every sender must
     either be in SPF with an aligned envelope domain or sign DKIM as d=<your domain> (delegated selectors). Start with p=none and
     read DMARC reports to find unknown senders before enforcing; use subdomains per vendor.
  C. Mailing list / forwarder that modifies messages: DKIM breaks on modification and SPF is evaluated against the list's IP, so DMARC
     can fail for legitimate mail (M3). Mitigations: list rewrites From to its own domain, ARC chains to preserve original results,
     or the sender domain uses p=none/quarantine. Plain forwarding without modification keeps DKIM valid (M6).
  None of the three replaces PGP/S/MIME: they authenticate DOMAINS/servers, in transit between MTAs, and protect nothing about the content from
  the mail servers themselves (no confidentiality, no per-user signature, no end-to-end non-repudiation); a compromised legitimate server
  or an authorised sender passes all three. PGP/S/MIME authenticate the individual and encrypt the content end to end.""")
