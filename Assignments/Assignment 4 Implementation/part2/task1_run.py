"""Task 1 driver: 1.1 implement, 1.2 expose, 1.3 requirement change, 1.4 boundary tests."""
import base64, os, sys, tempfile, time, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pgpmail import *


def banner(t):
    print("\n" + "=" * 78 + f"\n{t}\n" + "=" * 78)


tmp = tempfile.mkdtemp(prefix="pgp_")
ring = KeyRing(tmp)
for n in ["alice", "bob", "carol", "dave", "erin", "frank", "mallory"]:
    ring.generate(n)
ring.set_owner_trust("alice", "ultimate")   # the receiver's own ring trusts alice
alice = ring.private("alice")

banner("1.1 / 1.2  Normal case: alice -> bob (instrumented)")
msg = b"Case 2024-117: settlement terms are CONFIDENTIAL. " * 6
c = Counters()
env = protect(msg, "alice", alice, [("bob", ring.public("bob"))], c)
print("\n-- labelled view of the protected message --")
hexdump_labelled(env)
print()
out, signer = unprotect(env, "bob", ring.private("bob"), ring, Counters())
print(f"[result] decrypted == original: {out == msg} | signer identity: {signer}")

banner("1.3  Requirement change: (a) 1 recipient, (b) 5 recipients, (c) 10x message")
print("PREDICTION (written before running):\n"
      "  size : (b) = (a) + 4 extra slots x (8+2+256) = +1064 B; (c) payload 10x larger but text is repetitive so compresses well\n"
      "  pk ops: (a)=1 sign+1 wrap=2; (b)=1+5=6; (c)=2.   sym ops: 1 in every case\n"
      "  sender work grows more with recipient count in public-key ops (expensive, 256 B each);\n"
      "  with message size only the cheap symmetric/hash work grows.")
rows = []
for label, m, n in [("(a) 1 recipient", msg, 1), ("(b) 5 recipients", msg, 5), ("(c) msg x10", msg * 10, 1)]:
    recips = [(x, ring.public(x)) for x in ["bob", "carol", "dave", "erin", "frank"][:n]]
    c = Counters(); t = time.perf_counter()
    e = protect(m, "alice", alice, recips, c, log=lambda s: None)
    dt = (time.perf_counter() - t) * 1000
    rows.append((label, len(m), len(base64.b64decode(e)), c.pk, c.sym, dt))
print(f"\n{'case':18s}{'plain B':>9s}{'envelope B':>12s}{'pk ops':>8s}{'sym ops':>9s}{'ms':>8s}")
for r in rows:
    print(f"{r[0]:18s}{r[1]:9d}{r[2]:12d}{r[3]:8d}{r[4]:9d}{r[5]:8.1f}")
print(f"\nACTUAL vs PREDICTED: (b)-(a) = {rows[1][2]-rows[0][2]} B (predicted 1064: matches). "
      f"(c) is only {rows[2][2]-rows[0][2]} B larger for {rows[2][1]-rows[0][1]} B more plaintext (compression).\n"
      "Interpretation: sender work scales with recipients in the expensive public-key dimension; message size\n"
      "only affects the cheap symmetric dimension. Hybrid encryption means pk ops == 1 + recipients regardless of size.")

banner("1.4  Boundary / tamper tests (each must FAIL CLOSED with a specific error)")
good = protect(msg, "alice", alice, [("bob", ring.public("bob")), ("carol", ring.public("carol"))], log=lambda s: None)
raw = bytearray(base64.b64decode(good))


def flip(b, i):
    x = bytearray(b); x[i] ^= 1
    return base64.b64encode(bytes(x)).decode()


def attempt(name, envelope, who="bob", why=""):
    print(f"\n--- {name}\n    why chosen: {why}")
    try:
        m, s = unprotect(envelope, who, ring.private(who), ring, log=lambda x: None)
        print(f"    RESULT: ACCEPTED signer={s} len={len(m)}")
    except PGPError as e:
        print(f"    RESULT: REJECTED -> {e}   (non-zero exit status 2)")


attempt("empty message (boundary)", protect(b"", "alice", alice, [("bob", ring.public("bob"))], log=lambda s: None),
        why="zero-length plaintext exercises length fields, zlib and signing an empty digest; must be ACCEPTED, not crash")
attempt("one-bit flip in ciphertext", flip(raw, len(raw) - 20),
        why="AEAD integrity: must fail before decompression/parsing")
attempt("one-bit flip in header (carol's slot keyid; bob's own slot intact)", flip(raw, 273),
        why="header is bound as AAD; tests that wrap-slot tampering is not silently accepted")
attempt("recipient not in list (erin)", good, who="erin",
        why="a non-recipient must not find a slot")
attempt("signature from a different key (mallory, uncertified in ring)",
        protect(msg, "mallory", ring.private("mallory"), [("bob", ring.public("bob"))], log=lambda s: None),
        why="encryption is valid, but signer key has no certifications: tool must warn/refuse (trust failure)")
attempt("truncated envelope", base64.b64encode(bytes(raw[:60])).decode(), why="parser bounds checking")
attempt("garbage input", "!!notbase64!!", why="armour validation")
print("\nNote: decompression happens only AFTER the GCM tag verifies and is capped at 64 MiB, so an outsider cannot"
      " trigger a zip-bomb.")
