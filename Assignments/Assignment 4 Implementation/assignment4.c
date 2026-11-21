/*
 * CSA5111-CNS | Assignment 4 - Implementation
 * D Raghul | 192511115
 *
 * Implements the deterministic decision algorithms designed in Assignment 4:
 *   Q3  IPsec ESP anti-replay window (Tasks 3.1-3.4, desk-check with W=4)
 *   Q4  Corrected S/MIME certificate-validation decision (Tasks 4.2-4.4)
 *   Q5  PGP web-of-trust key evaluation (Task 5.1)
 *   Q5  Email header spam scoring (threshold >= 4)
 *
 * Cryptographic primitives (HASH/SIGN/AEAD/PK_ENCRYPT) are abstract in the
 * assignment, so certificates/ICV results are modelled as simple flags.
 *
 * Build: gcc assignment4.c -o assignment4
 */
#include <stdio.h>
#include <string.h>

/* ---------------------------- Q3: ESP anti-replay -------------------------- */
typedef struct {
    unsigned spi;
    unsigned long highest;
    unsigned bitmap;
    int window;
    int active;
} SA;

static void init_sa(SA *sa, unsigned spi, int w) {
    sa->spi = spi; sa->highest = 0; sa->bitmap = 0; sa->window = w; sa->active = 1;
}

/* Returns 1 = ACCEPT, 0 = DROP; reason written to *why */
static int process_esp(SA *sa, unsigned long seq, int icv_ok, const char **why) {
    if (!sa || !sa->active) { *why = "Unknown or inactive SA"; return 0; }
    if (!icv_ok) { *why = "Integrity check failed (state unchanged)"; return 0; }
    unsigned long S = seq, H = sa->highest;
    unsigned mask = (1u << sa->window) - 1;
    if (S > H) {
        unsigned long shift = S - H;
        if (shift >= (unsigned long)sa->window) sa->bitmap = 0;
        else sa->bitmap = (sa->bitmap << shift) & mask;
        sa->highest = S;
        sa->bitmap |= 1;
        *why = "New high sequence number";
        return 1;
    }
    unsigned long offset = H - S;
    if (offset >= (unsigned long)sa->window) { *why = "Sequence number too old"; return 0; }
    if (sa->bitmap & (1u << offset)) { *why = "Duplicate/replayed packet"; return 0; }
    sa->bitmap |= (1u << offset);
    *why = "Valid out-of-order packet";
    return 1;
}

static void print_bits(unsigned b, int w) {
    for (int i = w - 1; i >= 0; i--) putchar((b >> i) & 1 ? '1' : '0');
}

static void demo_replay(void) {
    printf("=== Q3: IPsec ESP anti-replay desk-check (W=4) ===\n");
    struct { unsigned long seq; int icv; } pk[] = {
        {1,1},{2,1},{5,1},{3,1},{2,1},{9,1},{4,1},{7,0},{7,1}
    };
    SA sa; init_sa(&sa, 0x1001, 4);
    printf("%-4s %-4s %-8s %-8s %-7s %s\n", "No", "Seq", "ICV", "Highest", "Bitmap", "Decision");
    for (int i = 0; i < 9; i++) {
        const char *why;
        int ok = process_esp(&sa, pk[i].seq, pk[i].icv, &why);
        printf("%-4d %-4lu %-8s %-8lu ", i + 1, pk[i].seq, pk[i].icv ? "Valid" : "Invalid", sa.highest);
        print_bits(sa.bitmap, 4);
        printf("    %s - %s\n", ok ? "ACCEPT" : "DROP", why);
    }
    printf("\n");
}

/* ------------------------ Q4: S/MIME certificate check --------------------- */
typedef struct {
    const char *subject_email;
    int chains_to_trusted_root;
    int within_validity;
    int allows_email_signing;
    int revoked;
    int signature_valid;
} Cert;

static const char *verify_signed_mail(const Cert *c, const char *expected_sender) {
    if (!c->chains_to_trusted_root) return "REJECT: Certificate chain is not trusted";
    if (!c->within_validity)        return "REJECT: Certificate expired or not yet valid";
    if (!c->allows_email_signing)   return "REJECT: Certificate usage is not permitted";
    if (strcmp(c->subject_email, expected_sender) != 0)
                                    return "REJECT: Certificate identity does not match sender";
    if (c->revoked)                 return "REJECT: Certificate revoked";
    if (!c->signature_valid)        return "REJECT: Signature invalid";
    return "ACCEPT";
}

static void demo_smime(void) {
    printf("=== Q4: S/MIME corrected validation ===\n");
    Cert mallory = {"alice@company.example", 0, 1, 1, 0, 1}; /* self-signed forgery */
    Cert alice   = {"alice@company.example", 1, 1, 1, 0, 1}; /* genuine */
    printf("Mallory self-signed cert : %s\n", verify_signed_mail(&mallory, "alice@company.example"));
    printf("Alice trusted cert       : %s\n", verify_signed_mail(&alice,   "alice@company.example"));
    printf("\n");
}

/* --------------------------- Q5: PGP web of trust -------------------------- */
typedef enum { UNTRUSTED, MARGINAL, FULL } Trust;
typedef struct { const char *name; Trust trust; int exists, expired_or_revoked, sig_ok; } Cert5;

static const char *evaluate_pgp_key(const Cert5 *sigs, int n, int unknown_evidence) {
    int full = 0, marginal = 0;
    for (int i = 0; i < n; i++) {
        if (!sigs[i].exists) { unknown_evidence = 1; continue; }
        if (sigs[i].expired_or_revoked) continue;
        if (!sigs[i].sig_ok) continue;
        if (sigs[i].trust == FULL) full++;
        else if (sigs[i].trust == MARGINAL) marginal++;
    }
    if (full >= 1 || marginal >= 2) return "VALID";
    if (unknown_evidence) return "UNKNOWN";
    return "INVALID";
}

static void demo_wot(void) {
    printf("=== Q5.1: PGP web-of-trust (Alice's key, Bob's policy) ===\n");
    Cert5 s[] = {
        {"Carol", FULL,      1, 0, 1},
        {"Dave",  MARGINAL,  1, 0, 1},
        {"Eve",   MARGINAL,  1, 0, 1},
        {"Frank", UNTRUSTED, 1, 0, 1},
    };
    printf("All four signatures      : %s\n", evaluate_pgp_key(s, 4, 0));
    printf("Only Carol (full)        : %s\n", evaluate_pgp_key(s, 1, 0));
    printf("Only Dave (marginal)     : %s\n", evaluate_pgp_key(s + 1, 1, 0));
    printf("Dave + Frank             : %s\n", evaluate_pgp_key((Cert5[]){s[1], s[3]}, 2, 0));
    printf("Unknown signer only      : %s\n", evaluate_pgp_key((Cert5[]){{"?", UNTRUSTED, 0, 0, 0}}, 1, 0));
    printf("\n");
}

/* ------------------------------ Spam scoring ------------------------------- */
typedef struct {
    int spf_fail_unaligned, dkim_fail, dmarc_fail, replyto_differs, suspicious_url, known_good;
} Mail;

static int spam_score(const Mail *m) {
    return 2 * m->spf_fail_unaligned + 2 * m->dkim_fail + 3 * m->dmarc_fail
         + 1 * m->replyto_differs + 2 * m->suspicious_url - 2 * m->known_good;
}

static void demo_spam(void) {
    printf("=== Q5: Spam/phishing scoring (threshold >= 4) ===\n");
    Mail phish = {1, 1, 1, 1, 1, 0};
    Mail good  = {0, 0, 0, 0, 0, 1};
    Mail edge  = {1, 0, 0, 1, 0, 0};
    Mail dkim  = {0, 1, 0, 0, 1, 0};
    struct { const char *n; Mail *m; } t[] = {
        {"Phishing mail", &phish}, {"Legitimate mail", &good},
        {"SPF fail + reply-to", &edge}, {"DKIM fail + bad URL", &dkim}
    };
    for (int i = 0; i < 4; i++) {
        int sc = spam_score(t[i].m);
        printf("%-22s score=%2d -> %s\n", t[i].n, sc, sc >= 4 ? "LIKELY SPAM/PHISHING" : "DELIVER/REVIEW");
    }
    printf("\n");
}

int main(void) {
    demo_replay();
    demo_smime();
    demo_wot();
    demo_spam();
    return 0;
}
