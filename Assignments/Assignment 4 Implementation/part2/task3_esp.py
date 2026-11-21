"""Task 3: ESP tunnel-mode packet processor with anti-replay, tamper handling and protection-coverage table.

ESP packet:  outer IPv4 header(20) | SPI(4) | SEQ(4) | IV(8) | AES-256-GCM( inner IP packet | pad | padlen | next-hdr ) | ICV(16)
GCM AAD = SPI || SEQ (so a modified sequence number fails the ICV; RFC 4106 style).
Keys are generated at run time (stand-in for IKE output); nothing is hard-coded."""
import hmac, hashlib, os, socket, struct, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

W_DEFAULT = 32
INTERNAL_LOG = []          # specific reasons (for the gateway administrator only)


def ilog(msg):
    INTERNAL_LOG.append(msg)


def ipv4_header(src, dst, proto, payload_len, ttl=64, ident=1):
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + payload_len, ident, 0, ttl, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    return hdr


def parse_ipv4(pkt):
    ver_ihl, tos, tot, ident, frag, ttl, proto, csum, src, dst = struct.unpack(">BBHHHBBH4s4s", pkt[:20])
    return dict(total=tot, ttl=ttl, proto=proto, src=socket.inet_ntoa(src), dst=socket.inet_ntoa(dst))


class SA:
    """Security Association. Outbound uses next_seq; inbound uses highest + bitmap."""
    def __init__(self, spi, key, salt, window=W_DEFAULT, max_seq=0xFFFFFFFF, peer="gw-lab"):
        self.spi, self.key, self.salt, self.window, self.max_seq, self.peer = spi, key, salt, window, max_seq, peer
        self.next_seq = 1
        self.highest = 0
        self.bitmap = 0
        self.active = True
        self.aead = AESGCM(key)

    # ---- anti-replay (RFC 4303 App. A style), bit 0 == highest
    def window_check(self, s):
        """Cheap pre-check; does NOT modify state. Returns (ok, reason)."""
        if s == 0:
            return False, "SEQ_ZERO"
        if s > self.highest:
            return True, "NEW_HIGH"
        offset = self.highest - s
        if offset >= self.window:
            return False, "TOO_OLD"
        if self.bitmap & (1 << offset):
            return False, "DUPLICATE"
        return True, "IN_WINDOW_UNSEEN"

    def window_update(self, s):
        """Only called AFTER the ICV has verified."""
        if s > self.highest:
            shift = s - self.highest
            self.bitmap = 0 if shift >= self.window else (self.bitmap << shift) & ((1 << self.window) - 1)
            self.highest = s
            self.bitmap |= 1
        else:
            self.bitmap |= 1 << (self.highest - s)

    def state(self):
        return f"highest={self.highest:3d} bitmap={self.bitmap:0{self.window}b}"


def new_sa_pair(spi, window=W_DEFAULT, max_seq=0xFFFFFFFF):
    key, salt = AESGCM.generate_key(256), os.urandom(4)       # stand-in for keys delivered by IKE
    return SA(spi, key, salt, window, max_seq), SA(spi, key, salt, window, max_seq)


class SeqExhausted(Exception):
    pass


def esp_encapsulate(sa, inner_ip_packet, gw_src="203.0.113.1", gw_dst="198.51.100.1"):
    """Tunnel mode: whole inner packet is the protected payload; new outer header added."""
    if sa.next_seq > sa.max_seq:
        sa.active = False
        raise SeqExhausted(f"SPI {sa.spi:#x}: sequence space exhausted -> must rekey (new SA)")
    seq = sa.next_seq; sa.next_seq += 1
    iv = os.urandom(8)
    pad = (-(len(inner_ip_packet) + 2)) % 4
    plaintext = inner_ip_packet + bytes(range(1, pad + 1)) + bytes([pad, 4])   # padlen, next-header=4 (IP-in-IP)
    aad = struct.pack(">II", sa.spi, seq)
    ct = sa.aead.encrypt(sa.salt + iv, plaintext, aad)                         # ciphertext || 16-byte ICV
    esp = aad + iv + ct
    return ipv4_header(gw_src, gw_dst, 50, len(esp)) + esp


def esp_process(sad, packet, trace=None):
    """Receiving gateway. Returns inner packet or None. EVERY failure returns the same None with no
    response/ICMP/timing-distinguishing output; the specific reason goes only to INTERNAL_LOG."""
    def drop(reason):
        ilog(reason)
        if trace is not None: trace.append(reason)
        return None
    if len(packet) < 20 + 8 + 8 + 16 + 4:
        return drop("MALFORMED: packet too short")
    spi, seq = struct.unpack(">II", packet[20:28])
    sa = sad.get(spi)
    if sa is None or not sa.active:
        return drop(f"UNKNOWN_SPI: {spi:#x}")
    ok, why = sa.window_check(seq)
    if not ok:
        return drop(f"REPLAY_CHECK seq={seq}: {why}")
    iv, ct = packet[28:36], packet[36:]
    try:
        plaintext = sa.aead.decrypt(sa.salt + iv, ct, packet[20:28])          # ICV verified here
    except InvalidTag:
        return drop(f"ICV_FAIL seq={seq} (window NOT updated)")
    sa.window_update(seq)                                                      # state changes only after ICV ok
    padlen, nxt = plaintext[-2], plaintext[-1]
    if nxt != 4 or padlen + 2 > len(plaintext):
        return drop("BAD_TRAILER")
    return plaintext[:len(plaintext) - 2 - padlen]


def inner_packet(n):
    payload = f"patient-lab-result #{n:03d}".encode()
    return ipv4_header("10.1.0.5", "10.2.0.9", 17, len(payload)) + payload


def banner(t):
    print("\n" + "=" * 78 + f"\n{t}\n" + "=" * 78)


# ============================================================================ Stage A
banner("Stage A - normal tunnel-mode protection (W=8 for readable bitmaps)")
out_sa, in_sa = new_sa_pair(0x1001, window=8)
sad = {in_sa.spi: in_sa}
print(f"SA: SPI={in_sa.spi:#x} AES-256-GCM, 4-byte salt + 8-byte IV nonce, ICV=16 B, window W={in_sa.window}, peer=gw-lab")
print(f"{'#':>2} {'SPI/SA':>9} {'seq':>4} {'ICV':>5} {'state after':<32} decapsulated inner packet")
for n in range(1, 6):
    pkt = esp_encapsulate(out_sa, inner_packet(n))
    spi, seq = struct.unpack(">II", pkt[20:28])
    tr = []
    inner = esp_process(sad, pkt, tr)
    ip = parse_ipv4(inner)
    print(f"{n:>2} {spi:#9x} {seq:>4} {'OK' if inner else 'FAIL':>5} {in_sa.state():<32} "
          f"{ip['src']}->{ip['dst']} proto={ip['proto']} data={inner[20:].decode()!r}")
print(f"outer header on wire: {parse_ipv4(pkt)['src']} -> {parse_ipv4(pkt)['dst']} proto=50 (ESP); inner addresses 10.x are hidden. "
      f"packet size {len(pkt)} B for a {len(inner)} B inner packet (overhead {len(pkt)-len(inner)} B)")

# ============================================================================ Stage B
banner("Stage B - replay and reordering (W=32)")
out_sa, in_sa = new_sa_pair(0x2002, window=32)
sad = {in_sa.spi: in_sa}
captured = {}
for n in range(1, 65):
    captured[n] = esp_encapsulate(out_sa, inner_packet(n))
HELD = {20, 31, 32, 33, 48}                     # delayed on the network
for n in range(1, 65):
    if n not in HELD:
        assert esp_process(sad, captured[n]) is not None
print(f"Setup: packets 1..64 sent; {sorted(HELD)} delayed in the network. After the rest arrive: {in_sa.state()}")
print("Window covers sequence numbers 33..64 (offset 0..31). Edge: seq 33 = offset 31 (last slot), seq 32 = offset 32 (just outside).\n")
tests = [
    ("(i)   exact replay of seq 64",                    "DROP  (duplicate bit set)",               lambda: captured[64]),
    ("(ii)  seq 48 delayed by 16 = W/2 positions",      "ACCEPT (inside window, bit clear)",       lambda: captured[48]),
    ("(iii) seq 20 delayed by 44 > W positions",        "DROP  (too old: offset 44 >= 32)",        lambda: captured[20]),
    ("(iv)  replay of seq 63 with seq field -> 200",    "DROP  (seq is in AAD: ICV fails, window untouched)",
        lambda: captured[63][:24] + struct.pack(">I", 200) + captured[63][28:]),
    ("(iv') replay of seq 63 with seq field -> 70",     "DROP  (ICV fails even though 70 would be a 'new high')",
        lambda: captured[63][:24] + struct.pack(">I", 70) + captured[63][28:]),
    ("(v)   BOUNDARY seq 33 (offset W-1 = 31)",         "ACCEPT (last slot of window, unseen)",    lambda: captured[33]),
    ("(vi)  BOUNDARY seq 32 (offset W = 32)",           "DROP  (first sequence outside window)",   lambda: captured[32]),
    ("(vii) seq 31 delayed, now offset 33",             "DROP  (too old)",                         lambda: captured[31]),
    ("(viii) seq 33 again (edge replay)",               "DROP  (duplicate)",                       lambda: captured[33]),
]
print(f"{'test':<48}{'PREDICTION':<52}{'ACTUAL':<10}{'state':<48}internal reason")
for name, pred, getter in tests:
    tr = []
    before = in_sa.state()
    res = esp_process(sad, getter(), tr)
    print(f"{name:<48}{pred:<52}{'ACCEPT' if res else 'DROP':<10}{in_sa.state():<48}{tr[0] if tr else 'ok'}")
print("\nFor (iv)/(iv') note highest stayed 64: an unauthenticated packet cannot move the window (integrity before state update).")

# ============================================================================ Stage C
banner("Stage C - tamper and misconfiguration")
out_sa, in_sa = new_sa_pair(0x3003, window=32, max_seq=3)
sad = {in_sa.spi: in_sa}
INTERNAL_LOG.clear()
good = esp_encapsulate(out_sa, inner_packet(1))
flipped = bytearray(good); flipped[40] ^= 0x01                                  # one payload byte
unknown = bytearray(good); unknown[20:24] = struct.pack(">I", 0xDEAD)           # unknown SPI
results = {
    "(i)   modified payload byte": esp_process(sad, bytes(flipped)),
    "(ii)  unknown SPI 0xDEAD": esp_process(sad, bytes(unknown)),
    "(iii-a) truncated packet": esp_process(sad, good[:30]),
}
for k, v in results.items():
    print(f"  external view  {k:<30}: dropped silently -> returns {v!r} (no ICMP, no error text, same code path/response)")
p2 = esp_encapsulate(out_sa, inner_packet(2)); p3 = esp_encapsulate(out_sa, inner_packet(3))
esp_process(sad, good); esp_process(sad, p2); esp_process(sad, p3)
print(f"  (iii-b) SA max_seq=3: three packets sent; sender now tries packet 4 ...")
try:
    esp_encapsulate(out_sa, inner_packet(4))
except SeqExhausted as e:
    print(f"    sender refuses to wrap the counter: {e}")
    out2, in2 = new_sa_pair(0x3004, window=32)
    sad[in2.spi] = in2
    in_sa.active = False
    print(f"    REKEY event: new SA SPI={in2.spi:#x} installed (keys would come from a fresh IKE CREATE_CHILD_SA); old SA retired")
    r = esp_process(sad, esp_encapsulate(out2, inner_packet(5)))
    print(f"    packet on new SA accepted: {r is not None}")
    r = esp_process(sad, esp_encapsulate(out_sa.__class__(0x3003, out_sa.key, out_sa.salt), inner_packet(6)))
    print(f"    late packet on retired SPI 0x3003 accepted: {r is not None}")
print("\n  INTERNAL log (administrator only, specific reasons):")
for line in INTERNAL_LOG:
    print("    -", line)
print("""
How information leakage is avoided: esp_process() has one failure exit (`drop`) that returns the identical value None
to the network layer. Nothing is sent back to the sender, so an attacker cannot learn whether the SPI, the
sequence number or the ICV was wrong; the reason is written only to the internal log. The ICV check uses AES-GCM
tag verification (constant-time compare inside the library). Remaining side channel: a cheap pre-check (unknown SPI /
replay) returns earlier than a full ICV verification; a production gateway would rate-limit and not expose timing to the sender.""")

# ============================================================================ Stage D
banner("Stage D - protection coverage table and NAT experiment")
table = [
    ("Original IP header",              "neither",       "ENCRYPT+AUTH (inner)", "AUTH (immutable fields; TTL/checksum zeroed)"),
    ("New outer IP header",             "n/a",           "neither",              "n/a"),
    ("ESP header (SPI, seq)",           "AUTH",          "AUTH",                 "n/a"),
    ("AH header (SPI, seq, ICV)",       "n/a",           "n/a",                  "AUTH"),
    ("TCP/UDP header + data",           "ENCRYPT+AUTH",  "ENCRYPT+AUTH",         "AUTH only (readable)"),
    ("ESP trailer (pad, next hdr)",     "ENCRYPT+AUTH",  "ENCRYPT+AUTH",         "n/a"),
]
print(f"{'packet part':<34}{'ESP-transport':<20}{'ESP-tunnel':<22}{'AH':<50}")
for r in table:
    print(f"{r[0]:<34}{r[1]:<20}{r[2]:<22}{r[3]:<50}")
print("""
Answers to the security team:
 1. Unprotected in transport mode: the ORIGINAL IP header (addresses, protocol, TTL, size) travels
    in clear and is not authenticated by ESP. In tunnel mode the original header is inside the encrypted+authenticated payload;
    only the NEW outer header (gateway addresses, protocol 50, size, TTL) is exposed and unauthenticated.""")

# NAT experiment: ESP covers SPI|SEQ|payload, AH covers immutable IP header fields as well
ahkey = os.urandom(32)


def ah_icv(ip_hdr, payload):
    h = bytearray(ip_hdr)
    h[8] = 0; h[10:12] = b"\0\0"          # TTL and checksum are mutable -> zeroed (src/dst are NOT mutable)
    return hmac.new(ahkey, bytes(h) + payload, hashlib.sha256).digest()[:16]


out_sa, in_sa = new_sa_pair(0x4004)
sad = {in_sa.spi: in_sa}
esp_pkt = esp_encapsulate(out_sa, inner_packet(1))
nat = bytearray(esp_pkt); nat[12:16] = socket.inet_aton("192.0.2.77")        # NAT rewrites outer source address
esp_ok = esp_process(sad, bytes(nat)) is not None
ah_payload = b"data"
ah_hdr = ipv4_header("203.0.113.1", "198.51.100.1", 51, len(ah_payload))
tag = ah_icv(ah_hdr, ah_payload)
nat_hdr = bytearray(ah_hdr); nat_hdr[12:16] = socket.inet_aton("192.0.2.77")
ah_ok = hmac.compare_digest(tag, ah_icv(bytes(nat_hdr), ah_payload))
print(f"""
 2. NAT experiment (outer source address rewritten 203.0.113.1 -> 192.0.2.77 in flight):
      ESP tunnel packet accepted after NAT : {esp_ok}   (ICV covers SPI|SEQ|encrypted payload, not the outer header)
      AH packet accepted after NAT         : {ah_ok}  (ICV covers the immutable IP header fields incl. source address)
    => AH integrity coverage includes the outer IP header, so any address-translating middlebox breaks it; ESP keeps
       working (NAT-T additionally wraps ESP in UDP/4500 so NAT can track the flow).
 3. Keys: SPIs, algorithms and keys are NOT configured by hand. IKEv2 (UDP 500/4500) first runs IKE_SA_INIT (Diffie-Hellman
    -> shared secret with forward secrecy, nonces) and IKE_AUTH (peers authenticate with certificates/PSK; the exchange
    is encrypted+integrity-protected with IKE_SA keys), which creates the first CHILD_SA (the ESP SA: SPI, algorithms,
    traffic selectors, keys derived via a PRF from SKEYSEED). IKE protects the negotiation against eavesdropping,
    tampering, peer impersonation and downgrade. Refresh: rekey by CREATE_CHILD_SA before lifetime (time/bytes) or
    before the 32-bit sequence space ends (Stage C-iii); install the new SA, then delete the old one; optional fresh DH
    for PFS. Compromise of a child SA key exposes only that SA's traffic.""")
