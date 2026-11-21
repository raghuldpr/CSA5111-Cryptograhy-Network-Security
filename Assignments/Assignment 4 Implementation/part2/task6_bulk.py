"""Task 6: secure mailing at scale - recipient key-state model, hybrid engine with key lifecycle, validation, growth.

Per-recipient wrap = ECIES-style: ephemeral X25519 -> ECDH -> HKDF-SHA256 -> AES-256-GCM(session key).
Message body is encrypted ONCE with AES-256-GCM under a fresh session key.  Keystore = JSON file (public data only);
recipient private keys exist only in the in-memory 'devices' dict used to simulate each recipient's decryption attempt."""
import base64, datetime as dt, hashlib, json, os, struct, sys, tempfile, time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidTag

UTC = dt.timezone.utc
NOW = dt.datetime.now(UTC)
RAW = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def banner(t):
    print("\n" + "=" * 78 + f"\n{t}\n" + "=" * 78)


# ----------------------------------------------------------------------- 6.2 key-state model
# Key[recipient] = (public_key, not_before, not_after, revoked, trust, fingerprint, superseded)
# state = f(record, now)  -- computed, never stored, so a stale flag cannot keep an expired key usable.
def key_state(rec, now=NOW):
    if rec is None:
        return "MISSING"
    if rec["revoked"]:
        return "REVOKED"                                   # terminal; wins over every other state
    if now < dt.datetime.fromisoformat(rec["not_before"]):
        return "NOT_YET_VALID"
    if now > dt.datetime.fromisoformat(rec["not_after"]):
        return "EXPIRED"
    if rec["trust"] != "verified":
        return "UNTRUSTED"                                 # fingerprint never verified
    if rec.get("superseded"):
        return "SUPERSEDED"                                # rolled over: new key preferred, old kept only for decrypting old mail
    return "ACTIVE"


ENCRYPTABLE = {"ACTIVE"}                                    # the ONLY state that allows encryption


class KeyStore:
    def __init__(self, path):
        self.path = path
        self.db = json.load(open(path)) if os.path.exists(path) else {}

    def save(self):
        json.dump(self.db, open(self.path, "w"))

    def add(self, who, pub_raw, days_valid=365, start_offset_days=-1, revoked=False, trust="verified"):
        nb = NOW + dt.timedelta(days=start_offset_days)
        na = nb + dt.timedelta(days=days_valid)
        self.db[who] = {"pub": base64.b64encode(pub_raw).decode(), "not_before": nb.isoformat(), "not_after": na.isoformat(),
                        "revoked": revoked, "trust": trust, "fingerprint": hashlib.sha256(pub_raw).hexdigest()[:16], "superseded": False}

    def rollover(self, who, new_pub_raw):
        """new key becomes ACTIVE; old one stays in history as SUPERSEDED"""
        self.db[who + "#old"] = dict(self.db[who], superseded=True)
        self.add(who, new_pub_raw)

    def revoke(self, who):
        self.db[who]["revoked"] = True


class Counters:
    def __init__(self):
        self.pk = 0; self.sym = 0


# ------------------------------------------------------------------------- engine
def _kek(shared, eph_pub, recip_pub):
    return HKDF(hashes.SHA256(), 32, salt=None, info=b"mail-wrap-v1" + eph_pub + recip_pub).derive(shared)


def wrap_for(recipient_pub_raw, session_key, c):
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(*RAW)
    shared = eph.exchange(X25519PublicKey.from_public_bytes(recipient_pub_raw)); c.pk += 1     # the public-key operation
    nonce = os.urandom(12)
    wrapped = AESGCM(_kek(shared, eph_pub, recipient_pub_raw)).encrypt(nonce, session_key, b"wrap")
    return hashlib.sha256(recipient_pub_raw).digest()[:8] + eph_pub + nonce + wrapped            # 8+32+12+48 = 100 B


def prepare_message(body, recipients, store, policy="skip", log=lambda s: None):
    """Returns (envelope|None, report). policy: 'skip' (send to valid, report skipped) or 'strict' (fail if any invalid)."""
    c = Counters()
    ok, skipped = [], []
    for r in recipients:
        rec = store.db.get(r)
        st = key_state(rec)
        (ok if st in ENCRYPTABLE else skipped).append((r, st))
        log(f"    {r:<14} state={st}")
    if (policy == "strict" and skipped) or not ok:
        return None, dict(ok=ok, skipped=skipped, pk=0, sym=0, size=0, error="no valid recipients" if not ok else "strict policy: invalid recipient present")
    session_key = AESGCM.generate_key(256)
    nonce = os.urandom(12)
    slots = b"".join(wrap_for(base64.b64decode(store.db[r]["pub"]), session_key, c) for r, _ in ok)
    header = b"MSG1" + struct.pack(">I", len(ok)) + slots + nonce
    ct = AESGCM(session_key).encrypt(nonce, body, header); c.sym += 1                             # body encrypted ONCE
    env = header + ct
    return env, dict(ok=ok, skipped=skipped, pk=c.pk, sym=c.sym, size=len(env), error=None)


def try_decrypt(env, who, priv):
    """Recipient side: locate own slot, unwrap, decrypt. Returns plaintext or reason string."""
    n = struct.unpack_from(">I", env, 4)[0]
    my_pub = priv.public_key().public_bytes(*RAW)
    kid = hashlib.sha256(my_pub).digest()[:8]
    for i in range(n):
        slot = env[8 + 100 * i: 8 + 100 * (i + 1)]
        if slot[:8] == kid:
            eph_pub, nonce, wrapped = slot[8:40], slot[40:52], slot[52:]
            try:
                shared = priv.exchange(X25519PublicKey.from_public_bytes(eph_pub))
                key = AESGCM(_kek(shared, eph_pub, my_pub)).decrypt(nonce, wrapped, b"wrap")
                hdr_end = 8 + 100 * n + 12
                return AESGCM(key).decrypt(env[hdr_end - 12:hdr_end], env[hdr_end:], env[:hdr_end])
            except (InvalidTag, ValueError):
                return "unwrap/decrypt failed (modified or malformed)"
    return "no slot for this key"


def new_users(names):
    keys = {n: X25519PrivateKey.generate() for n in names}
    return keys, {n: k.public_key().public_bytes(*RAW) for n, k in keys.items()}


# ============================================================================ 6.1
banner("6.1 Model the problem")
print("""INPUT   : message body M; recipient list R (addresses); key store with a record per recipient; current time.
OUTPUT  : one envelope containing a single encrypted body + one wrapped session key per ELIGIBLE recipient, and a report
          (who was encrypted for, who was skipped and why, size, public-key / symmetric operation counts).
OBJECTIVE: confidentiality of M for exactly the recipients whose keys are currently valid and trusted; no silent failure.
CONSTRAINTS: keys expire, are revoked, replaced; large lists; body encrypted once; a recipient address alone says nothing about
          which key to use or whether it may still be used.
PER-RECIPIENT DATA REQUIRED: public key itself, validity period (not_before/not_after), revocation status, trust level
          (was the fingerprint verified?), fingerprint (to detect substitution), supersession (rolled over?).""")

banner("6.2 Key-state model")
print("""Key[recipient] = (public_key, not_before, not_after, revoked, trust, fingerprint, superseded)
  public_key   X25519 key to which the session key is wrapped.     fingerprint  SHA-256 prefix, compared out-of-band to detect substitution.
  validity     [not_before, not_after]; outside it the key is NOT_YET_VALID / EXPIRED.
  revoked      set by the owner/CA; terminal and overrides every other field.
  trust        'verified' only after the fingerprint was checked; otherwise UNTRUSTED.
  superseded   set on the OLD record when a rollover installs a new key.
State is computed from the record at send time (never cached):
    MISSING -> (add key) -> UNTRUSTED -> (verify fingerprint) -> ACTIVE -> (rollover) -> SUPERSEDED
    ACTIVE/SUPERSEDED/UNTRUSTED -> EXPIRED (time passes)       any state -> REVOKED (terminal)
  Encryption ALLOWED only in : ACTIVE
  Encryption BLOCKED in       : MISSING, UNTRUSTED, NOT_YET_VALID, EXPIRED, REVOKED, SUPERSEDED (use the new key)
Session key combination: one fresh 256-bit session key K encrypts the body once; K is wrapped separately under EACH ACTIVE recipient key.
Invalid recipient policy: default 'skip + report to sender' (others still get the message and the sender sees the exact reason);
  'strict' mode fails the whole message if ANY recipient is invalid; zero valid recipients always fails.""")

# ============================================================================ 6.3
banner("6.3 Engine on a 12-entry list (8 valid, 1 expired, 1 revoked, 1 untrusted, 1 not in key store)")
tmpd = tempfile.mkdtemp(prefix="bulk_")
store = KeyStore(os.path.join(tmpd, "keystore.json"))
names = [f"user{i}" for i in range(1, 13)]
devices, pubs = new_users(names)
for i, n in enumerate(names[:8]):
    store.add(n, pubs[n])
store.add("user9", pubs["user9"], days_valid=100, start_offset_days=-200)        # expired 100 days ago
store.add("user10", pubs["user10"]); store.revoke("user10")
store.add("user11", pubs["user11"], trust="unverified")
# user12 intentionally not in store
store.save()
body = os.urandom(2000)
env, rep = prepare_message(body, names, store, log=print)
nv, ns = len(rep["ok"]), len(rep["skipped"])
from collections import Counter
reasons = Counter(s for _, s in rep["skipped"])
print(f"\nRecipients valid: {nv} | skipped: {ns} ({', '.join(f'{v} {k.lower()}' for k, v in reasons.items())})")
print(f"Public-key operations: {rep['pk']} | Symmetric operations: {rep['sym']} | final message size: {rep['size']} B (body {len(body)} B)")
for r, st in rep["skipped"]:
    print(f"  skipped {r}: {st} -> sender notified")
store_ok = KeyStore(store.path)
print(f"keystore persisted to file ({os.path.getsize(store.path)} B JSON), reloaded {len(store_ok.db)} records")

# ============================================================================ 6.4
banner("6.4 Validate: 5 recipients (3 valid, 1 expired, 1 revoked) - hand derivation vs actual decryption")
names5 = ["alice", "bob", "carol", "dave", "erin"]
dev5, pub5 = new_users(names5)
s5 = KeyStore(os.path.join(tmpd, "ks5.json"))
for n in ("alice", "bob", "carol"):
    s5.add(n, pub5[n])
s5.add("dave", pub5["dave"], days_valid=30, start_offset_days=-60)      # expired 30 days ago
s5.add("erin", pub5["erin"]); s5.revoke("erin")
hand = {"alice": True, "bob": True, "carol": True, "dave": False, "erin": False}
print("HAND DERIVATION (before running): alice, bob, carol ACTIVE -> can decrypt; dave EXPIRED (not_after in the past) -> no slot;"
      " erin REVOKED -> no slot.")
msg5 = b"Newsletter: maintenance window Sunday 02:00."
env5, rep5 = prepare_message(msg5, names5, s5)
print(f"engine: valid={[r for r,_ in rep5['ok']]} skipped={rep5['skipped']}")
print(f"\n{'recipient':<10}{'expected':<10}{'ACTUAL decrypt attempt':<44}{'match'}")
allmatch = True
for n in names5:
    res = try_decrypt(env5, n, dev5[n])
    can = res == msg5
    allmatch &= can == hand[n]
    print(f"{n:<10}{str(hand[n]):<10}{('plaintext recovered' if can else res):<44}{can == hand[n]}")
print(f"ALL MATCH: {allmatch}")
# extra: tampered header fails for everyone (AAD)
bad = bytearray(env5); bad[8 + 200] ^= 1      # flip a bit in carol's slot; alice's own slot is untouched
print(f"tampered header -> alice: {try_decrypt(bytes(bad), 'alice', dev5['alice'])}")
# rollover test
newk = X25519PrivateKey.generate()
s5.rollover("alice", newk.public_key().public_bytes(*RAW))
print(f"after rollover alice: old record state={key_state(s5.db['alice#old'])}, new record state={key_state(s5.db['alice'])}; "
      "old private key can no longer read NEW mail:", try_decrypt(prepare_message(msg5, ['alice'], s5)[0], 'alice', dev5['alice']))
print("""
Why this validation raises confidence: the expected outcome was derived from the written rules BEFORE running, and it was checked
end-to-end against the cryptographic reality (does a given private key actually open the envelope) rather than against the engine's own
report. The negative cases (expired, revoked) show the engine never wrapped for them, and the tamper and rollover checks show failures
are specific. A bug that flagged state correctly but still wrapped the key (or the reverse) would be caught by the decrypt attempt.""")

# ============================================================================ 6.5
banner("6.5 Growth in cost (body = 10,000 B, all recipients ACTIVE)")
print(f"{'Recipients':>10}{'PK ops':>9}{'Sym ops':>9}{'Msg size B':>12}{'bytes/recip':>13}{'Time ms':>10}")
big = os.urandom(10_000)
rows = []
for n in (1, 10, 100, 1000, 10000):
    ks = KeyStore(os.path.join(tmpd, f"g{n}.json"))
    ds, ps = new_users([f"u{i}" for i in range(n)])
    for u, p in ps.items(): ks.add(u, p)
    t = time.perf_counter()
    e, r = prepare_message(big, list(ps), ks)
    dtm = (time.perf_counter() - t) * 1000
    rows.append((n, r["pk"], r["sym"], r["size"], dtm))
    print(f"{n:>10}{r['pk']:>9}{r['sym']:>9}{r['size']:>12}{(r['size'] - len(big) - 16 - 20) / n:>13.1f}{dtm:>10.1f}")
    if n == 100:   # decrypt spot check
        assert try_decrypt(e, "u57", ds["u57"]) == big
print("""
Inquiry: the body is encrypted ONCE (sym ops stays 1 and the 10,000 B body is stored once) - that is why hybrid encryption beats
encrypting the whole message per recipient. But the session key must reach EVERY recipient, and a key can only be protected with
that recipient's own public key: one wrap (1 public-key operation, 100 B slot) per recipient. So per-recipient work and
per-recipient bytes are constant, total pk operations and message size grow linearly: size ~ body + 100*n, pk ops = n.
Time is dominated by those n wraps, but ops/bytes (not time) are the reliable evidence.""")

banner("6.6 Business change: 200,000 subscribers")
print(f"""From the table: ~100 B and 1 public-key op per recipient. For 200,000 subscribers that is ~{100*200000/1e6:.0f} MB of wrapped keys in EVERY
message (versus a few KB of body) and 200,000 key agreements per send, plus 200,000 key records to validate/expire/revoke/roll over.
 * Why per-recipient wrapping is impractical: header >> body, linear public-key work for every newsletter, and the key-state
   machine of 6.2 must be correct for every one of 200,000 records at send time.
 * Property that changed: from 'a few named recipients, each with an individually managed key' to 'a very large, open audience whose
   membership changes constantly'; confidentiality is wanted per SUBSCRIBER SET, not per individually authenticated person.
 * Strategy to investigate instead: authenticated delivery - email carries only a notification with a short-lived, single-use link to an
   HTTPS portal (TLS 1.3) where each subscriber logs in; or TLS-protected hop-by-hop delivery; or group keys (a rotating broadcast key
   distributed once per epoch via a tree/KEK hierarchy, so a send costs one symmetric encryption).
 * What is given up/weakened: end-to-end confidentiality against the provider/portal operator (they hold plaintext or the group key);
   per-user cryptographic non-repudiation; a leaked group key/link exposes everyone in the epoch (needs rotation on every leave =
   rekey cost); link-forwarding can share content unless access is authenticated; dependence on the portal's availability and security.""")

banner("6.7 Technical reflection (<=150 words)")
text = ("Hybrid encryption removed the cost of encrypting the body per recipient: in 6.5 the body was encrypted once (1 symmetric "
        "operation) regardless of n. But the confidentiality of that body now rests entirely on the wrapped session keys, so every "
        "recipient's public key must be correct and current. My 6.3/6.4 runs show the dangerous cases: an expired key (dave), a revoked "
        "key (erin), an unverified key and a missing key must be refused, or the message is encrypted to someone who should no longer "
        "read it - or to an attacker's substituted key - while still appearing 'encrypted'. Efficiency cannot repair a wrong key "
        "set; it makes failure cheaper to scale. Key validity, revocation, rollover and fingerprint verification remain the security "
        "problem, and their cost grows linearly with recipients (n wraps, n records).")
print(text, f"\n[{len(text.split())} words]")
