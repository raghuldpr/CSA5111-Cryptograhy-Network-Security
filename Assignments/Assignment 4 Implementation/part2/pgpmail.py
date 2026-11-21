"""Task 1 - PGP-style secure mail engine (hybrid encryption + signature + key rings).

Design (from Part I, Task 2):  sign(HASH(M)) -> package(M, sig, signer-id) -> COMPRESS
 -> AES-256-GCM with fresh session key -> wrap session key per recipient (RSA-OAEP)
 -> envelope -> base64 armour.
Envelope layout (binary, big-endian):
  magic "PGPX" | ver(1) | n_recipients(2) | [keyid(8) | wlen(2) | wrapped]* | nonce(12) | clen(4) | ciphertext+tag
Header bytes (everything before clen) are bound into GCM as AAD.
Private keys live only in key-ring files created at run time (never in source, never logged).
"""
import base64, hashlib, json, os, struct, zlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature, InvalidTag

MAGIC, VERSION = b"PGPX", 1
MAX_DECOMPRESSED = 64 * 1024 * 1024
_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
_OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


class PGPError(Exception):
    """A failed check; .step names the check that rejected the message."""
    def __init__(self, step, msg):
        super().__init__(f"[{step}] {msg}")
        self.step = step


class Counters:
    def __init__(self):
        self.pk = 0; self.sym = 0; self.hash = 0

    def __repr__(self):
        return f"pk_ops={self.pk} sym_ops={self.sym} hash_ops={self.hash}"


# ----------------------------------------------------------------- key ring
def _spki(public_key):
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def key_id(public_key):
    return hashlib.sha256(_spki(public_key)).digest()[:8]


def fingerprint(public_key):
    return hashlib.sha256(_spki(public_key)).hexdigest()


class KeyRing:
    """name -> {keyid, owner_trust, certified_by[], revoked}. Keys stored as PEM files in a directory."""
    def __init__(self, directory):
        self.dir = directory
        os.makedirs(directory, exist_ok=True)
        self.meta_path = os.path.join(directory, "ring.json")
        self.meta = json.load(open(self.meta_path)) if os.path.exists(self.meta_path) else {}

    def _save(self):
        json.dump(self.meta, open(self.meta_path, "w"), indent=1)

    def generate(self, name, bits=2048):
        priv = rsa.generate_private_key(65537, bits)
        path = os.path.join(self.dir, f"{name}.key.pem")
        with open(path, "wb") as f:
            f.write(priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
        try: os.chmod(path, 0o600)
        except OSError: pass
        self.import_public(name, priv.public_key())
        return priv

    def import_public(self, name, pub, owner_trust="unknown"):
        with open(os.path.join(self.dir, f"{name}.pub.pem"), "wb") as f:
            f.write(pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        self.meta.setdefault(name, {"owner_trust": owner_trust, "certified_by": [], "revoked": False})
        self.meta[name]["keyid"] = key_id(pub).hex()
        self._save()

    def public(self, name):
        return serialization.load_pem_public_key(open(os.path.join(self.dir, f"{name}.pub.pem"), "rb").read())

    def private(self, name):
        return serialization.load_pem_private_key(open(os.path.join(self.dir, f"{name}.key.pem"), "rb").read(), None)

    def by_keyid(self, kid_hex):
        for n, m in self.meta.items():
            if m["keyid"] == kid_hex:
                return n
        return None

    def certify(self, signer, target):
        """Web-of-trust certification: signer signs the target's fingerprint."""
        sig = self.private(signer).sign(fingerprint(self.public(target)).encode(), _PSS, hashes.SHA256())
        self.meta[target]["certified_by"].append({"signer": signer, "sig": base64.b64encode(sig).decode()})
        self._save()

    def set_owner_trust(self, name, level):
        self.meta[name]["owner_trust"] = level
        self._save()

    def validity(self, target, log=print):
        """PGP rule: >=1 FULL or >=2 MARGINAL valid certifications => VALID; else UNKNOWN/INVALID."""
        full = marginal = 0
        fp = fingerprint(self.public(target)).encode()
        for c in self.meta[target]["certified_by"]:
            s = c["signer"]
            if s not in self.meta or self.meta[s]["revoked"]:
                log(f"    certification by {s}: ignored (unknown/revoked signer)")
                continue
            try:
                self.public(s).verify(base64.b64decode(c["sig"]), fp, _PSS, hashes.SHA256())
            except InvalidSignature:
                log(f"    certification by {s}: BAD SIGNATURE")
                continue
            t = self.meta[s]["owner_trust"]
            log(f"    certification by {s}: signature ok, owner_trust={t}")
            full += t in ("full", "ultimate")
            marginal += t == "marginal"
        if full >= 1 or marginal >= 2:
            verdict = "VALID"
        else:
            verdict = "INVALID" if self.meta[target]["certified_by"] else "UNKNOWN"
        log(f"    => {target}: full={full} marginal={marginal} -> {verdict}")
        return verdict


# ------------------------------------------------------------------- sender
def protect(message: bytes, sender, sender_priv, recipients, counters=None, log=print):
    """recipients: list of (name, public_key). Returns the armoured envelope (str)."""
    c = counters or Counters()
    log(f"[send] plaintext length          : {len(message)} bytes")
    digest = hashlib.sha256(message).digest(); c.hash += 1
    sig = sender_priv.sign(digest, _PSS, hashes.SHA256()); c.pk += 1
    log(f"[send] SHA-256 digest            : {digest.hex()[:16]}...  signed with {sender}'s private key (RSA-PSS), sig={len(sig)} B")
    signer_kid = key_id(sender_priv.public_key())
    package = struct.pack(">8sHI", signer_kid, len(sig), len(message)) + sig + message
    compressed = zlib.compress(package, 9)
    log(f"[send] signed package            : {len(package)} B -> compressed {len(compressed)} B (ratio {len(compressed)/len(package):.2f})")
    session_key = os.urandom(32)
    nonce = os.urandom(12)
    session_id = hashlib.sha256(session_key).hexdigest()[:12]
    log(f"[send] session-key identifier    : {session_id} (fingerprint only, key not shown)")
    header = MAGIC + struct.pack(">BH", VERSION, len(recipients))
    for name, pub in recipients:
        wrapped = pub.encrypt(session_key, _OAEP); c.pk += 1
        header += struct.pack(">8sH", key_id(pub), len(wrapped)) + wrapped
        log(f"[send] session key wrapped for   : {name} (keyid {key_id(pub).hex()}) RSA-OAEP -> {len(wrapped)} B")
    header += nonce
    ciphertext = AESGCM(session_key).encrypt(nonce, compressed, header); c.sym += 1  # header is AAD
    envelope = header + struct.pack(">I", len(ciphertext)) + ciphertext
    log(f"[send] AES-256-GCM               : {len(compressed)} B -> {len(ciphertext)} B (incl. 16 B tag); header bound as AAD")
    armoured = base64.b64encode(envelope).decode()
    log(f"[send] envelope {len(envelope)} B -> base64 armour {len(armoured)} chars | {c}")
    return armoured


# ----------------------------------------------------------------- receiver
def unprotect(armoured: str, me, my_priv, ring: KeyRing, counters=None, log=print, require_valid_key=True):
    """Fail-closed. Returns (message, signer_name). Raises PGPError naming the rejecting step."""
    c = counters or Counters()
    try:
        env = base64.b64decode(armoured, validate=True)
    except Exception:
        raise PGPError("armour", "not valid base64")
    try:
        if env[:4] != MAGIC:
            raise PGPError("parse", "bad magic")
        ver, n = struct.unpack_from(">BH", env, 4)
        if ver != VERSION:
            raise PGPError("parse", f"unsupported version {ver}")
        off, entries = 7, {}
        for _ in range(n):
            kid, wl = struct.unpack_from(">8sH", env, off); off += 10
            entries[kid] = env[off:off + wl]; off += wl
        header_end = off + 12
        nonce = env[off:header_end]
        (clen,) = struct.unpack_from(">I", env, header_end)
        ciphertext = env[header_end + 4: header_end + 4 + clen]
        if len(ciphertext) != clen or len(env) != header_end + 4 + clen or len(nonce) != 12:
            raise PGPError("parse", "length mismatch / truncated")
    except struct.error:
        raise PGPError("parse", "truncated envelope")
    header = env[:header_end]
    log(f"[recv] parsed: {n} recipient slot(s), nonce 12 B, ciphertext {clen} B")
    my_kid = key_id(my_priv.public_key())
    if my_kid not in entries:
        raise PGPError("recipient", f"{me}: no session-key slot for key {my_kid.hex()} (not a recipient)")
    log(f"[recv] check 1 PASS: slot found for {me} (keyid {my_kid.hex()})")
    try:
        session_key = my_priv.decrypt(entries[my_kid], _OAEP); c.pk += 1
    except ValueError:
        raise PGPError("unwrap", "session-key unwrap failed")
    log(f"[recv] check 2 PASS: session key unwrapped with {me}'s private key (RSA-OAEP)")
    try:
        compressed = AESGCM(session_key).decrypt(nonce, ciphertext, header); c.sym += 1
    except InvalidTag:
        raise PGPError("aead", "authentication tag mismatch - ciphertext/header modified")
    log("[recv] check 3 PASS: AES-GCM tag verified (nothing decompressed before this point)")
    try:
        d = zlib.decompressobj()
        package = d.decompress(compressed, MAX_DECOMPRESSED)
        if d.unconsumed_tail:
            raise PGPError("decompress", "decompressed size limit exceeded")
    except zlib.error:
        raise PGPError("decompress", "corrupt compressed data")
    try:
        skid, slen, mlen = struct.unpack_from(">8sHI", package, 0)
        sig = package[14:14 + slen]
        message = package[14 + slen:]
        if len(sig) != slen or len(message) != mlen:
            raise PGPError("parse", "signed package length mismatch")
    except struct.error:
        raise PGPError("parse", "signed package truncated")
    log(f"[recv] check 4 PASS: decompressed {len(compressed)} B -> {len(package)} B, parsed (signer keyid {skid.hex()})")
    signer = ring.by_keyid(skid.hex())
    if signer is None:
        raise PGPError("signer", f"unknown signer key {skid.hex()}")
    if require_valid_key:
        log(f"[recv] key-ring validity of signer {signer}:")
        v = ring.validity(signer, log=lambda s: log("[recv]" + s))
        if v != "VALID" and ring.meta[signer]["owner_trust"] != "ultimate":
            raise PGPError("trust", f"signer key '{signer}' is {v}: insufficient certifications (WARNING: key not validated)")
    digest = hashlib.sha256(message).digest(); c.hash += 1
    try:
        ring.public(signer).verify(sig, digest, _PSS, hashes.SHA256()); c.pk += 1
    except InvalidSignature:
        raise PGPError("signature", f"signature does not verify under {signer}'s key")
    log(f"[recv] check 5 PASS: RSA-PSS signature valid, signer identity = {signer} | {c}")
    return message, signer


def hexdump_labelled(armoured, log=print):
    env = base64.b64decode(armoured)
    n = struct.unpack_from(">H", env, 5)[0]
    off = 7
    parts = [("magic 'PGPX'", 0, 4), ("version", 4, 5), ("recipient count", 5, 7)]
    for i in range(n):
        wl = struct.unpack_from(">H", env, off + 8)[0]
        parts += [(f"recip[{i}] keyid", off, off + 8), (f"recip[{i}] wrapped length", off + 8, off + 10),
                  (f"recip[{i}] RSA-OAEP wrapped session key", off + 10, off + 10 + wl)]
        off += 10 + wl
    parts += [("GCM nonce", off, off + 12), ("ciphertext length", off + 12, off + 16),
              ("ciphertext (compressed signed package)", off + 16, len(env) - 16), ("GCM tag", len(env) - 16, len(env))]
    for name, a, b in parts:
        shown = env[a:b][:16].hex(" ") + (" ..." if b - a > 16 else "")
        log(f"  {a:5d}-{b:5d} ({b-a:4d} B) {name:42s} {shown}")
    log("  base64 (first 96 chars): " + armoured[:96] + "...")
