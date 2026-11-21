"""Shared PKI: root CA -> intermediate CA -> users, CRLs, server certs. Built with `cryptography`.
All keys are generated at run time into a work directory (test keys only, nothing hard-coded)."""
import datetime as dt, os
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

UTC = dt.timezone.utc


def now():
    return dt.datetime.now(UTC)


def _name(cn, email=None):
    attrs = [x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SIMATS Test PKI"), x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    return x509.Name(attrs)


def _write(path, obj, private=False):
    with open(path, "wb") as f:
        if private:
            f.write(obj.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        else:
            f.write(obj.public_bytes(serialization.Encoding.PEM))


class Authority:
    def __init__(self, cn, parent=None, workdir=".", days=3650, path_len=None, start=None, end=None):
        self.cn, self.parent, self.dir = cn, parent, workdir
        self.key = rsa.generate_private_key(65537, 2048)
        subject = _name(cn)
        issuer_key = parent.key if parent else self.key
        issuer_name = parent.cert.subject if parent else subject
        start = start or now() - dt.timedelta(days=1)
        end = end or start + dt.timedelta(days=days)
        b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer_name)
             .public_key(self.key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(start).not_valid_after(end)
             .add_extension(x509.BasicConstraints(ca=True, path_length=path_len), critical=True)
             .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
             .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()), False))
        if parent:
            b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(parent.key.public_key()), False)
        self.cert = b.sign(issuer_key, hashes.SHA256())
        self.revoked = []
        self.crl_number = 1
        slug = cn.replace(" ", "_")
        _write(os.path.join(workdir, slug + ".crt"), self.cert)
        _write(os.path.join(workdir, slug + ".key"), self.key, private=True)
        self.path = os.path.join(workdir, slug + ".crt")

    def issue(self, name, email=None, dns=None, purpose="email", start=None, end=None, days=365):
        key = rsa.generate_private_key(65537, 2048)
        start = start or now() - dt.timedelta(hours=1)
        end = end or start + dt.timedelta(days=days)
        sans = []
        if email: sans.append(x509.RFC822Name(email))
        if dns: sans += [x509.DNSName(d) for d in ([dns] if isinstance(dns, str) else dns)]
        b = (x509.CertificateBuilder().subject_name(_name(name)).issuer_name(self.cert.subject)
             .public_key(key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(start).not_valid_after(end)
             .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
             .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
             .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()), False))
        if sans: b = b.add_extension(x509.SubjectAlternativeName(sans), False)
        if purpose == "email":
            b = (b.add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), critical=True)
                 .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]), False))
        elif purpose == "server":
            b = (b.add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), critical=True)
                 .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False))
        elif purpose == "client":
            b = (b.add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
                 .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False))
        cert = b.sign(self.key, hashes.SHA256())
        base = os.path.join(self.dir, name.replace(" ", "_"))
        _write(base + ".crt", cert); _write(base + ".key", key, private=True)
        return cert, key, base

    def revoke(self, cert):
        self.revoked.append(cert.serial_number)

    def write_crl(self, path):
        b = (x509.CertificateRevocationListBuilder().issuer_name(self.cert.subject)
             .last_update(now() - dt.timedelta(hours=1)).next_update(now() + dt.timedelta(days=7)))
        for sn in self.revoked:
            b = b.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(sn)
                                          .revocation_date(now() - dt.timedelta(minutes=5)).build())
        crl = b.sign(self.key, hashes.SHA256())
        with open(path, "wb") as f:
            f.write(crl.public_bytes(serialization.Encoding.PEM))
        return crl


def build_hierarchy(workdir):
    """root CA -> intermediate CA -> alice, bob (+ extra identities used by failure tests)."""
    os.makedirs(workdir, exist_ok=True)
    root = Authority("Test Root CA", None, workdir, path_len=1)
    inter = Authority("Test Intermediate CA", root, workdir, days=1825, path_len=0)
    return root, inter
