"""Task 2: S/MIME (OpenSSL CMS over a root->intermediate->user hierarchy) vs PGP-style (Task 1 tool, web of trust)."""
import base64, datetime as dt, os, subprocess, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pki import *
import pgpmail
from pgpmail import KeyRing, Counters, PGPError

OPENSSL = os.environ.get("OPENSSL", "openssl")
W = tempfile.mkdtemp(prefix="smime_")


def banner(t):
    print("\n" + "=" * 78 + f"\n{t}\n" + "=" * 78)


def ossl(*args, input_bytes=None):
    """Run openssl in the work directory (relative file names avoid Windows path quoting problems)."""
    p = subprocess.run([OPENSSL, *args], cwd=W, input=input_bytes, capture_output=True)
    return p.returncode, p.stdout, p.stderr.decode(errors="replace").strip()


def wr(name, data):
    with open(os.path.join(W, name), "wb") as f:
        f.write(data)


def rd(name):
    return open(os.path.join(W, name), "rb").read()


def short(path):
    return os.path.basename(path)


# ------------------------------------------------------------------ PKI
root, inter = build_hierarchy(W)
alice_c, _, a_base = inter.issue("Alice", email="alice@company.example")
bob_c, _, b_base = inter.issue("Bob", email="bob@company.example")
alice, bob = short(a_base), short(b_base)
# failure-case identities
exp_c, _, e_base = inter.issue("Expired Eve", email="eve@company.example",
                               start=now() - dt.timedelta(days=400), end=now() - dt.timedelta(days=35))
rev_c, _, r_base = inter.issue("Revoked Rita", email="rita@company.example")
inter.revoke(rev_c)
rogue_root = Authority("Rogue Root CA", None, W, path_len=0)
rog_c, _, g_base = rogue_root.issue("Mallory", email="alice@company.example")   # claims alice's address
expired, revoked, rogue = short(e_base), short(r_base), short(g_base)
root.write_crl(os.path.join(W, "root.crl.pem"))
inter.write_crl(os.path.join(W, "inter.crl.pem"))
wr("crls.pem", rd("root.crl.pem") + rd("inter.crl.pem"))
print(f"[pki] work dir {W}\n[pki] chain: Test Root CA -> Test Intermediate CA -> {{Alice, Bob, Expired Eve, Revoked Rita}}; "
      "plus Rogue Root CA -> Mallory (claims alice@company.example)")
print(f"[pki] revoked serial in intermediate CRL: {inter.revoked[0]:x}")

MSG = b"Subject: Q3 results\r\n\r\nQuarterly revenue is 14.2M. Do not forward.\r\n"
wr("msg.txt", MSG)
CERT_STATS = {"pk_sender": 0}


def smime_sign(signer, include_inter=True, out="signed.der", nodetach=True):
    args = ["cms", "-sign", "-in", "msg.txt", "-signer", f"{signer}.crt", "-inkey", f"{signer}.key",
            "-md", "sha256", "-binary", "-outform", "DER", "-out", out]
    if nodetach: args.append("-nodetach")
    if include_inter: args += ["-certfile", "Test_Intermediate_CA.crt"]
    return ossl(*args)


def smime_encrypt(recip, inp="signed.der", out="enc.der"):
    return ossl("cms", "-encrypt", "-binary", "-aes-256-cbc", "-in", inp, "-inform", "DER", "-outform", "DER",
                "-out", out, f"{recip}.crt")


def smime_receive(recip, inp="enc.der", expect_email=None, verbose=True, signed_in=None):
    """Receiver: decrypt (if encrypted), then verify with the full validation sequence, reporting each step."""
    steps = []
    if inp is not None:
        rc, _, err = ossl("cms", "-decrypt", "-in", inp, "-inform", "DER", "-recip", f"{recip}.crt",
                          "-inkey", f"{recip}.key", "-binary", "-out", "dec.der")
        if rc: return False, [f"step 1 DECRYPT          FAIL: {err}"], None
        steps.append(f"step 1 DECRYPT          PASS (content-encryption key unwrapped with {recip}'s private key)")
        signed = "dec.der"
    else:
        signed = signed_in
    # step 2: CMS signature/digest check only (signer cert is verified separately in step 3)
    for f in ("signer_out.pem", "certs_out.pem", "plain_out.txt"):
        if os.path.exists(os.path.join(W, f)): os.remove(os.path.join(W, f))
    rc, _, err = ossl("cms", "-verify", "-in", signed, "-inform", "DER", "-noverify", "-binary",
                      "-signer", "signer_out.pem", "-certsout", "certs_out.pem", "-out", "plain_out.txt")
    if rc:
        steps.append(f"step 2 SIGNATURE         FAIL -> openssl: {err.splitlines()[-1] if err else '(no message)'}")
        return False, steps, err
    steps.append("step 2 SIGNATURE         PASS (SHA-256 digest of content matches signed attributes; RSA signature valid)")
    # step 3: certificate path, validity, purpose, revocation, e-mail identity (all must hold)
    vargs = ["verify", "-show_chain", "-CAfile", "Test_Root_CA.crt", "-untrusted", "certs_out.pem",
             "-CRLfile", "crls.pem", "-crl_check_all", "-purpose", "smimesign"]
    if expect_email: vargs += ["-verify_email", expect_email]
    rc, out, err = ossl(*vargs, "signer_out.pem")
    if rc:
        msg = " | ".join(l for l in (err + chr(10) + out.decode(errors="replace")).splitlines() if "error" in l.lower() or "unable" in l.lower() or "expired" in l.lower() or "revoked" in l.lower() or "mismatch" in l.lower())
        steps.append(f"step 3 CERT VALIDATION   FAIL -> openssl: {msg[:230] or err[:230]}")
        return False, steps, err
    c = x509.load_pem_x509_certificate(rd("signer_out.pem"))
    san = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.RFC822Name)
    cn = c.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    steps += [f"step 3a SIGNER CERT        {cn} <{san[0]}> serial {c.serial_number:x}",
              "step 3b CHAIN BUILD         leaf -> Test Intermediate CA -> Test Root CA (trusted anchor, -CAfile)",
              f"step 3c VALIDITY PERIOD     {c.not_valid_before_utc:%Y-%m-%d} .. {c.not_valid_after_utc:%Y-%m-%d} contains now",
              "step 3d KEY USAGE / EKU     emailProtection + digitalSignature (-purpose smimesign)",
              "step 3e REVOCATION          CRLs for intermediate and root consulted (-crl_check_all): not revoked",
              f"step 3f EMAIL IDENTITY      {'matches expected ' + expect_email if expect_email else 'not checked'}",
]
    return True, steps, cn


def case(title, predict, fn):
    print(f"\n--- {title}\n    PREDICTION: {predict}")
    ok, steps, info = fn()
    for s in steps: print("    " + s)
    print(f"    ACTUAL: {'ACCEPTED' if ok else 'REJECTED'}")
    return ok


# -------------------------------------------------------------- 2.1 normal
banner("2.1 Normal case")
print("SOLUTION A - S/MIME (sign-then-encrypt, Alice -> Bob)")
smime_sign(alice); signed_len = len(rd("signed.der"))
smime_encrypt(bob); enc_len = len(rd("enc.der"))
ok, steps, _ = smime_receive(bob, expect_email="alice@company.example")
for s in steps: print("  " + s)
print(f"  RESULT: {'ACCEPTED' if ok else 'REJECTED'}; plaintext recovered == original: {rd('plain_out.txt').replace(b'\\r\\n', b'\\n') == MSG.replace(b'\\r\\n', b'\\n')}")
print(f"  sizes: message {len(MSG)} B, signed CMS {signed_len} B (includes Alice cert + intermediate cert), encrypted CMS {enc_len} B")
cert_bytes = len(alice_c.public_bytes(serialization.Encoding.DER)) + len(inter.cert.public_bytes(serialization.Encoding.DER))
print(f"  certificate overhead inside message: {cert_bytes} B (Alice leaf + intermediate)")

print("\nSOLUTION B - PGP-style (Task 1 tool, web-of-trust ring)")
ring = KeyRing(os.path.join(W, "pgpring"))
for n in ["alice", "bob", "carol", "dave", "mallory"]:
    ring.generate(n)
ring.set_owner_trust("carol", "full")
ring.set_owner_trust("dave", "marginal")
ring.certify("carol", "alice")                      # carol (fully trusted introducer) signed alice's key
ring.certify("carol", "dave")
pg_env = pgpmail.protect(MSG, "alice", ring.private("alice"), [("bob", ring.public("bob"))], Counters(), log=lambda s: None)
pgc = Counters()
m, signer = pgpmail.unprotect(pg_env, "bob", ring.private("bob"), ring, pgc, log=lambda s: print("  " + s))
pg_len = len(base64.b64decode(pg_env))
print(f"  RESULT: ACCEPTED signer={signer}; plaintext ok: {m == MSG}")
pub_overhead = len(ring.public("alice").public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
cert_sig = len(base64.b64decode(ring.meta["alice"]["certified_by"][0]["sig"]))
print(f"  sizes: PGP envelope {pg_len} B (signer key NOT included; receiver already holds it in the ring)")
print(f"  key overhead if sender attached key + 1 certification: {pub_overhead + cert_sig} B")

# -------------------------------------------------------------- 2.2 failures
banner("2.2 Break the trust assumptions (S/MIME: 6 failure cases; PGP: 1)")


def run_signed_case(signer_name, **kw):
    def go():
        rc, _, err = smime_sign(signer_name, include_inter=kw.get("include_inter", True))
        if rc: return False, [f"sign failed: {err}"], None
        smime_encrypt(bob)
        return smime_receive(bob, expect_email=kw.get("expect", None) or None)
    return go


case("F1 Expired certificate (Expired Eve, valid until 35 days ago)",
     "REJECT at step 'validity period' (openssl: certificate has expired)",
     run_signed_case(expired, expect="eve@company.example"))
case("F2 Certificate issued by an untrusted CA (Rogue Root -> Mallory)",
     "REJECT at chain building (self-signed root not in trust store)",
     run_signed_case(rogue, include_inter=False, expect="alice@company.example"))
case("F3 Sender e-mail does not match certificate (Bob's valid cert, receiver expects alice@company.example)",
     "REJECT at identity step: chain is fine but certificate email != claimed sender",
     run_signed_case(bob, expect="alice@company.example"))
case("F4 Revoked certificate (Revoked Rita, serial in intermediate CRL)",
     "REJECT at revocation step (CRL check)",
     run_signed_case(revoked, expect="rita@company.example"))


def tamper():
    smime_sign(alice)
    data = bytearray(rd("signed.der"))
    i = data.find(b"14.2M")
    data[i:i + 5] = b"41.2M"                                   # flip digits inside the signed content
    wr("tampered.der", bytes(data))
    return smime_receive(None, inp=None, expect_email="alice@company.example", signed_in="tampered.der")


case("F5 Tampered message body (14.2M -> 41.2M inside the signed content)",
     "REJECT at final signature step (digest mismatch); chain/identity steps would pass", tamper)
case("F6 Intermediate certificate missing from the message and from the verifier's store",
     "REJECT at chain building (unable to get local issuer certificate)",
     run_signed_case(alice, include_inter=False, expect="alice@company.example"))

print("\nPGP failure: key not validated (insufficient signatures)")
print("    PREDICTION: mallory's key has 0 certifications -> UNKNOWN -> tool warns and refuses")
env_m = pgpmail.protect(MSG, "mallory", ring.private("mallory"), [("bob", ring.public("bob"))], log=lambda s: None)
try:
    pgpmail.unprotect(env_m, "bob", ring.private("bob"), ring, log=lambda s: print("    " + s))
except PGPError as e:
    print(f"    ACTUAL: REJECTED -> {e}")
ring.certify("dave", "mallory")
print("    Now dave (only MARGINAL trust) certifies mallory: 1 marginal < 2 needed:")
try:
    pgpmail.unprotect(env_m, "bob", ring.private("bob"), ring, log=lambda s: print("    " + s))
except PGPError as e:
    print(f"    ACTUAL: REJECTED -> {e}")

# -------------------------------------------------------------- 2.3 comparison
banner("2.3 Engineering comparison (operation counts, sizes, steps, trust)")
sm_sign_only = len(rd("signed.der"))
print(f"{'metric':44s}{'S/MIME (A)':>26s}{'PGP-style (B)':>26s}")
rows = [
    ("public-key ops, sender", "2", "2"),
    ("public-key ops, receiver (1st msg from sender)", "4", "3 (1 cert path)"),
    ("public-key ops, receiver (later messages)", "2 (if chain cached)", "2 (validity cached)"),
    ("signed+encrypted message size (bytes)", str(enc_len), str(pg_len)),
    ("  of which certificate/key material", f"{cert_bytes}", "0 (key already in ring)"),
    ("message size if sender attaches identity", f"{enc_len}", f"{pg_len + pub_overhead + cert_sig}"),
]
for r in rows: print(f"{r[0]:44s}{r[1]:>26s}{r[2]:>26s}")
print(f"PGP receiver counters as measured: {pgc}  (+1 certification-signature verify done inside KeyRing.validity, not counted by the counter => 3 total, matching the table)")
print("""
Steps to verify a NEW sender the receiver has never met:
  S/MIME: (1) take cert + intermediate from the message  (2) build chain to a root already in the trust store
          (3) check validity, key usage, email identity, CRL/OCSP.  No human action if the CA is already trusted.
  PGP   : (1) obtain sender's public key (keyserver / attached)  (2) look for certifications from keys already in the
          ring  (3) compute full/marginal counts  (4) if < threshold: human must verify the fingerprint out-of-band
          and sign the key (or accept a warning).  Observed: mallory with 0/1-marginal certifications was refused.
What must the receiver trust:
  S/MIME: the configured root CA, and (transitively) every CA below it that the root authorised - hierarchical, centralised.
  PGP   : each introducer individually (owner trust per person) - decentralised, subjective, per-receiver policy.""")

banner("2.4 Changed requirement: 5,000 employees + customers across several organisations")
print("""Observation 2.1-2.3 shows S/MIME's receiver needs only one pre-installed root to verify a never-met sender
(F2 and F6 show the chain to a trusted root is the unit of trust: a rogue root or missing intermediate fails at chain building), whereas PGP verified alice only because carol, an introducer already in bob's ring, had signed
her key; mallory (no path) was refused with a warning. With 5,000 people across organisations, a receiver would
need a trusted-introducer path to each unknown sender: the web grows O(n^2) in the worst case and every receiver
holds different, personally curated trust. Conclusion: choose S/MIME with a CA hierarchy (per organisation
intermediates, cross-trusted roots or a shared public CA) - verification of strangers needs no manual step, revocation
is centrally published (F4 proved the CRL check blocks Rita), at the cost of trusting the CA and operating a PKI.""")
