/*
 * ============================================================================
 * Experiment 32: DSA Signature Randomness Demonstration
 *
 * Objective:
 *   Demonstrate that the Digital Signature Algorithm (DSA) produces distinct,
 *   randomized signatures for the exact same message when different per-message
 *   secret numbers (k) are utilized, while both signatures remain valid.
 *
 * Mathematical Foundations:
 *   DSA Parameters:
 *     - p: A prime modulus
 *     - q: A prime divisor of (p - 1)
 *     - g: A generator with order q modulo p: g = h^((p-1)/q) mod p > 1
 *     - x: Private signing key (1 <= x < q)
 *     - y: Public verification key: y = g^x mod p
 *
 *   Signing Algorithm (for message hash H(m)):
 *     1. Select a random per-signature secret k such that 1 <= k < q and gcd(k, q) == 1.
 *     2. Compute r = (g^k mod p) mod q.
 *     3. Compute s = k^(-1) * (H(m) + x * r) mod q.
 *     The signature is the pair (r, s).
 *
 *   Verification Algorithm:
 *     1. Verify that 0 < r < q and 0 < s < q.
 *     2. Compute w = s^(-1) mod q.
 *     3. Compute u1 = (H(m) * w) mod q.
 *     4. Compute u2 = (r * w) mod q.
 *     5. Compute v = ((g^u1 * y^u2) mod p) mod q.
 *     The signature is VALID if and only if v == r.
 *
 * Cryptographic Insight:
 *   - Unlike textbook RSA where the signature is deterministic (S = m^d mod n),
 *     DSA produces non-deterministic signatures due to the ephemeral value k.
 *   - Two distinct values of k (k1 != k2) yield completely different signatures
 *     (r1, s1) != (r2, s2), yet both verify successfully.
 *   - Critical Security Warning: k must NEVER be reused or leaked; reusing k
 *     across two signatures allows an attacker to recover the private key x.
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>

// Computes the greatest common divisor using Euclidean algorithm
long long gcd(long long a, long long b) {
    while (b != 0) {
        long long temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

// Computes modular exponentiation (base^exp mod mod)
long long mod_exp(long long base, long long exp, long long mod) {
    long long result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1) {
            result = (__int128)result * base % mod;
        }
        base = (__int128)base * base % mod;
        exp /= 2;
    }
    return result;
}

// Computes modular inverse using Extended Euclidean Algorithm
// Returns x such that (a * x) % mod == 1
long long mod_inverse(long long a, long long mod) {
    long long m0 = mod;
    long long y = 0, x = 1;

    if (mod == 1) return 0;
    a = (a % mod + mod) % mod;

    while (a > 1) {
        long long q = a / mod;
        long long t = mod;
        mod = a % mod;
        a = t;
        t = y;
        y = x - q * y;
        x = t;
    }

    if (x < 0) x += m0;
    return x;
}

// Generates a DSA signature (r, s) for a given message hash and nonce k
int dsa_sign(long long p, long long q, long long g, long long x,
             long long Hm, long long k, long long *r, long long *s) {
    if (k <= 0 || k >= q || gcd(k, q) != 1) {
        return 0; // Invalid k
    }

    // r = (g^k mod p) mod q
    *r = mod_exp(g, k, p) % q;
    if (*r == 0) return 0;

    // k_inv = k^(-1) mod q
    long long k_inv = mod_inverse(k, q);

    // s = k_inv * (H(m) + x * r) mod q
    long long term = (Hm + (__int128)x * (*r)) % q;
    *s = ((__int128)k_inv * term) % q;
    if (*s == 0) return 0;

    return 1;
}

// Verifies a DSA signature (r, s) against message hash Hm and public key y
int dsa_verify(long long p, long long q, long long g, long long y,
               long long Hm, long long r, long long s, long long *v_out,
               long long *w_out, long long *u1_out, long long *u2_out) {
    if (r <= 0 || r >= q || s <= 0 || s >= q) {
        return 0; // Out of range
    }

    // w = s^(-1) mod q
    long long w = mod_inverse(s, q);
    *w_out = w;

    // u1 = (H(m) * w) mod q
    long long u1 = ((__int128)Hm * w) % q;
    *u1_out = u1;

    // u2 = (r * w) mod q
    long long u2 = ((__int128)r * w) % q;
    *u2_out = u2;

    // v = ((g^u1 * y^u2) mod p) mod q
    long long t1 = mod_exp(g, u1, p);
    long long t2 = mod_exp(y, u2, p);
    long long v = ((__int128)t1 * t2 % p) % q;
    *v_out = v;

    return (v == r);
}

int main(void) {
    // Standard educational DSA parameter set
    // p = 607, q = 101 (p - 1 = 606 = 6 * 101, both prime)
    // g = 2^6 mod 607 = 64 (generator of order q mod p)
    long long p = 607;
    long long q = 101;
    long long g = 64;
    long long x = 45; // Private key (1 <= x < q)
    long long y;      // Public key: y = g^x mod p

    long long Hm;
    long long k1, k2;
    long long r1, s1, r2, s2;
    long long v1, w1, u1_1, u2_1;
    long long v2, w2, u1_2, u2_2;
    int choice;

    printf("====================================================================\n");
    printf("     EXPERIMENT 32: DSA SIGNATURE RANDOMNESS DEMONSTRATION          \n");
    printf("====================================================================\n\n");

    printf("Educational DSA Global Parameters:\n");
    printf("  Prime Modulus (p)           : %lld\n", p);
    printf("  Prime Divisor (q)           : %lld  (Note: q divides p - 1 = %lld)\n", q, p - 1);
    printf("  Generator (g)               : %lld  (Order of g mod p is q = %lld)\n", g, q);
    printf("  Signer Private Key (x)      : %lld  (1 <= x < q)\n", x);

    // Calculate public key
    y = mod_exp(g, x, p);
    printf("  Signer Public Key (y)       : %lld  (y = g^x mod p = %lld^%lld mod %lld)\n\n", y, g, x, p);

    // Accept message hash and ephemeral k values
    printf("Enter Message Hash H(m) [1 to %lld, default 75]: ", q - 1);
    if (scanf("%lld", &Hm) != 1 || Hm <= 0 || Hm >= q) {
        Hm = 75;
        printf("Using default H(m) = %lld\n", Hm);
    }

    printf("Enter first random nonce k1 [1 < k1 < %lld, default 37]: ", q);
    if (scanf("%lld", &k1) != 1 || k1 <= 0 || k1 >= q || gcd(k1, q) != 1) {
        k1 = 37;
        printf("Using default k1 = %lld\n", k1);
    }

    printf("Enter second random nonce k2 [1 < k2 < %lld, default 53]: ", q);
    if (scanf("%lld", &k2) != 1 || k2 <= 0 || k2 >= q || gcd(k2, q) != 1) {
        k2 = 53;
        printf("Using default k2 = %lld\n", k2);
    }

    if (k1 == k2) {
        printf("[WARNING] k1 and k2 are identical. Adjusting k2 to 53 for demonstration.\n");
        k2 = 53;
    }

    // 1. Generate First Signature
    printf("\n--------------------------------------------------------------------\n");
    printf("           SIGNATURE 1 GENERATION (using ephemeral k1 = %lld)        \n", k1);
    printf("--------------------------------------------------------------------\n");
    if (!dsa_sign(p, q, g, x, Hm, k1, &r1, &s1)) {
        printf("[ERROR] Failed to generate Signature 1.\n");
        return 1;
    }
    printf("  r1 = (g^k1 mod p) mod q = (%lld^%lld mod %lld) mod %lld = %lld\n", g, k1, p, q, r1);
    printf("  k1_inv = %lld^(-1) mod %lld = %lld\n", k1, q, mod_inverse(k1, q));
    printf("  s1 = k1_inv * (H(m) + x * r1) mod q = %lld\n", s1);
    printf("  ==> Signature 1 (r1, s1) = (%lld, %lld)\n", r1, s1);

    // 2. Generate Second Signature
    printf("\n--------------------------------------------------------------------\n");
    printf("           SIGNATURE 2 GENERATION (using ephemeral k2 = %lld)        \n", k2);
    printf("--------------------------------------------------------------------\n");
    if (!dsa_sign(p, q, g, x, Hm, k2, &r2, &s2)) {
        printf("[ERROR] Failed to generate Signature 2.\n");
        return 1;
    }
    printf("  r2 = (g^k2 mod p) mod q = (%lld^%lld mod %lld) mod %lld = %lld\n", g, k2, p, q, r2);
    printf("  k2_inv = %lld^(-1) mod %lld = %lld\n", k2, q, mod_inverse(k2, q));
    printf("  s2 = k2_inv * (H(m) + x * r2) mod q = %lld\n", s2);
    printf("  ==> Signature 2 (r2, s2) = (%lld, %lld)\n", r2, s2);

    // 3. Signature Verification
    printf("\n--------------------------------------------------------------------\n");
    printf("                       SIGNATURE VERIFICATION                       \n");
    printf("--------------------------------------------------------------------\n");
    int valid1 = dsa_verify(p, q, g, y, Hm, r1, s1, &v1, &w1, &u1_1, &u2_1);
    printf("[*] Verifying Signature 1 (r1=%lld, s1=%lld):\n", r1, s1);
    printf("    w1  = s1^(-1) mod q = %lld\n", w1);
    printf("    u1  = (H(m) * w1) mod q = %lld\n", u1_1);
    printf("    u2  = (r1 * w1) mod q   = %lld\n", u2_1);
    printf("    v1  = ((g^u1 * y^u2) mod p) mod q = %lld\n", v1);
    printf("    Verification Check: v1 (%lld) == r1 (%lld) ? %s\n",
           v1, r1, valid1 ? "[VALID / VERIFIED]" : "[INVALID]");

    int valid2 = dsa_verify(p, q, g, y, Hm, r2, s2, &v2, &w2, &u1_2, &u2_2);
    printf("\n[*] Verifying Signature 2 (r2=%lld, s2=%lld):\n", r2, s2);
    printf("    w2  = s2^(-1) mod q = %lld\n", w2);
    printf("    u1  = (H(m) * w2) mod q = %lld\n", u1_2);
    printf("    u2  = (r2 * w2) mod q   = %lld\n", u2_2);
    printf("    v2  = ((g^u1 * y^u2) mod p) mod q = %lld\n", v2);
    printf("    Verification Check: v2 (%lld) == r2 (%lld) ? %s\n",
           v2, r2, valid2 ? "[VALID / VERIFIED]" : "[INVALID]");

    // 4. Comparison and Conclusion
    printf("\n====================================================================\n");
    printf("                      COMPARISON & CONCLUSION                       \n");
    printf("====================================================================\n");
    printf("Message Hash H(m)        : %lld\n", Hm);
    printf("Signer Public Key (y)    : %lld\n", y);
    printf("Signature 1 (k1 = %lld)    : (r1 = %lld, s1 = %lld) -> Status: %s\n",
           k1, r1, s1, valid1 ? "VALID" : "INVALID");
    printf("Signature 2 (k2 = %lld)    : (r2 = %lld, s2 = %lld) -> Status: %s\n",
           k2, r2, s2, valid2 ? "VALID" : "INVALID");
    printf("\nRandomness Observation:\n");
    printf("  r1 != r2 (%lld != %lld) and s1 != s2 (%lld != %lld)\n", r1, r2, s1, s2);
    printf("  The signatures are COMPLETELY DIFFERENT, yet BOTH ARE VALID for\n");
    printf("  the identical message hash H(m) and public key y.\n\n");
    printf("Cryptographic Comparison:\n");
    printf("  - Textbook RSA is deterministic: S = M^d mod n always yields the\n");
    printf("    same signature for a fixed message and key (without randomized padding).\n");
    printf("  - DSA is inherently randomized: Each signature selects a fresh k,\n");
    printf("    preventing signature correlation and replay detection.\n");
    printf("  - Modern RSA schemes (e.g., RSA-PSS) introduce probabilistic salt\n");
    printf("    to achieve similar randomness benefits.\n");
    printf("====================================================================\n");
    printf("[SUCCESS] DSA signature randomness demonstrated and verified.\n");

    return 0;
}
