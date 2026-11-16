/*
 * ============================================================================
 * Experiment 28: Diffie-Hellman Key Exchange Protocol
 * 
 * Objective:
 *   Implement the Diffie-Hellman key exchange protocol, compute public keys
 *   and matching shared secrets, demonstrate the mathematical flaw in
 *   swapping base and exponent (x^a vs a^x), and analyze security against
 *   eavesdropping and Man-in-the-Middle (MitM) attacks.
 * 
 * Mathematical Formulation of Diffie-Hellman:
 *   1. Public Parameters: Prime q, Primitive root generator a
 *   2. Private Keys: Alice chooses x, Bob chooses y (where 1 < x, y < q)
 *   3. Public Keys Transmitted over Public Channel:
 *        Alice: A = (a^x) mod q
 *        Bob  : B = (a^y) mod q
 *   4. Shared Secret Computed Locally:
 *        Alice computes: K1 = (B^x) mod q = (a^y)^x mod q = a^(xy) mod q
 *        Bob computes  : K2 = (A^y) mod q = (a^x)^y mod q = a^(xy) mod q
 *        Since a^(xy) = a^(yx), K1 = K2 = K (Shared Secret Key).
 * 
 * Discrete Logarithm Problem (DLP):
 *   Given public a, q, A = (a^x) mod q, it is computationally infeasible to
 *   find x when q is a large prime.
 * 
 * Analysis of Flawed Alternative (x^a mod q, y^a mod q):
 *   If Alice sends A' = (x^a) mod q and Bob sends B' = (y^a) mod q:
 *   The proposed shared value (x*y)^a mod q = (A' * B') mod q.
 *   Eve intercepts A' and B' and simply computes (A' * B') mod q directly,
 *   completely breaking confidentiality without finding x or y!
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>

// Modular exponentiation using Repeated Squaring: (base^exp) mod mod
long long mod_exp(long long base, long long exp, long long mod) {
    long long result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp & 1) {
            result = (__int128)result * base % mod;
        }
        base = (__int128)base * base % mod;
        exp >>= 1;
    }
    return result;
}

int main(void) {
    long long q, a, x, y;
    long long A, B;
    long long K1, K2;

    printf("====================================================================\n");
    printf("   EXP 28: DIFFIE-HELLMAN KEY EXCHANGE PROTOCOL                    \n");
    printf("====================================================================\n\n");

    // 1. Inputs
    printf("Enter public prime number q    (e.g., 23): ");
    if (scanf("%lld", &q) != 1 || q <= 2) {
        printf("Error: Invalid prime number q.\n");
        return 1;
    }

    printf("Enter public generator a       (e.g., 5) : ");
    if (scanf("%lld", &a) != 1 || a <= 0 || a >= q) {
        printf("Error: Generator a must satisfy 0 < a < q.\n");
        return 1;
    }

    printf("Enter Alice's private key x    (e.g., 6) : ");
    if (scanf("%lld", &x) != 1 || x <= 0 || x >= q) {
        printf("Error: Alice's private key must satisfy 0 < x < q.\n");
        return 1;
    }

    printf("Enter Bob's private key y      (e.g., 15): ");
    if (scanf("%lld", &y) != 1 || y <= 0 || y >= q) {
        printf("Error: Bob's private key must satisfy 0 < y < q.\n");
        return 1;
    }

    // 2. Compute Public Keys
    A = mod_exp(a, x, q);
    B = mod_exp(a, y, q);

    printf("\n--------------------------------------------------------------------\n");
    printf("1. PUBLIC KEY GENERATION & EXCHANGE:\n");
    printf("--------------------------------------------------------------------\n");
    printf("Public Parameters           : Prime q = %lld, Base a = %lld\n", q, a);
    printf("Alice's Private Key (x)     : %lld\n", x);
    printf("Bob's Private Key (y)       : %lld\n", y);
    printf("Alice's Public Key A        : A = (a^x) mod q = (%lld^%lld) mod %lld = %lld\n",
           a, x, q, A);
    printf("Bob's Public Key B          : B = (a^y) mod q = (%lld^%lld) mod %lld = %lld\n",
           a, y, q, B);
    printf("Transmitted across channel  : Alice sends A = %lld, Bob sends B = %lld\n", A, B);

    // 3. Compute Shared Secret
    K1 = mod_exp(B, x, q);
    K2 = mod_exp(A, y, q);

    printf("\n--------------------------------------------------------------------\n");
    printf("2. SHARED SECRET CALCULATION:\n");
    printf("--------------------------------------------------------------------\n");
    printf("Alice computes secret K1    : K1 = (B^x) mod q = (%lld^%lld) mod %lld = %lld\n",
           B, x, q, K1);
    printf("Bob computes secret K2      : K2 = (A^y) mod q = (%lld^%lld) mod %lld = %lld\n",
           A, y, q, K2);

    printf("\n====================================================================\n");
    printf("PROTOCOL VERIFICATION:\n");
    printf("====================================================================\n");
    if (K1 == K2) {
        printf("[SUCCESS] Both parties derived matching shared secret key K = %lld!\n", K1);
    } else {
        printf("[FAILED] Shared secrets do not match!\n");
    }

    // 4. Mathematical Comparison: Flawed scheme (x^a mod q, y^a mod q)
    printf("\n--------------------------------------------------------------------\n");
    printf("3. COMPARISON: ANALYSIS OF FLAWED PROPOSAL (x^a mod q, y^a mod q)\n");
    printf("--------------------------------------------------------------------\n");
    long long flawed_A = mod_exp(x, a, q);
    long long flawed_B = mod_exp(y, a, q);
    long long eve_computed_shared = (long long)(((__int128)flawed_A * flawed_B) % q);
    long long direct_product_pow  = mod_exp((x * y) % q, a, q);

    printf("Proposed Exchange:\n");
    printf("  Alice sends A' = (x^a) mod q = (%lld^%lld) mod %lld = %lld\n",
           x, a, q, flawed_A);
    printf("  Bob sends   B' = (y^a) mod q = (%lld^%lld) mod %lld = %lld\n",
           y, a, q, flawed_B);
    printf("  Target shared value: (x * y)^a mod q = %lld\n", direct_product_pow);
    printf("\nEavesdropper (Eve's) Calculation:\n");
    printf("  Eve intercepts A' = %lld and B' = %lld from public channel.\n", flawed_A, flawed_B);
    printf("  Eve computes: (A' * B') mod q = (%lld * %lld) mod %lld = %lld\n",
           flawed_A, flawed_B, q, eve_computed_shared);
    printf("  Does Eve obtain the exact shared value? %s (Eve gets %lld!)\n",
           (eve_computed_shared == direct_product_pow) ? "YES! FULLY COMPROMISED" : "NO",
           eve_computed_shared);

    // 5. Security & Theoretical Discussion
    printf("\n====================================================================\n");
    printf("SECURITY & THEORETICAL ANALYSIS:\n");
    printf("====================================================================\n");
    printf("1. Flaw in (x^a mod q):\n");
    printf("   In (x^a mod q), exponentiation distributes over multiplication:\n");
    printf("     (x^a * y^a) mod q = (x * y)^a mod q\n");
    printf("   This allows an eavesdropper to compute the shared value by a simple\n");
    printf("   modular multiplication of public messages. It provides NO secrecy.\n");
    printf("\n2. Why Standard Diffie-Hellman Works:\n");
    printf("   Standard DH uses (a^x mod q) and (a^y mod q). Multiplying public keys gives:\n");
    printf("     (a^x * a^y) mod q = a^(x + y) mod q  !=  a^(x * y) mod q\n");
    printf("   To find a^(xy), an attacker must solve the Computational Diffie-Hellman\n");
    printf("   (CDH) problem, which is tied to the hardness of Discrete Logarithms (DLP).\n");
    printf("\n3. Man-in-the-Middle (MitM) Vulnerability:\n");
    printf("   Standard Diffie-Hellman does NOT provide authentication. An active attacker\n");
    printf("   can establish separate keys with Alice and Bob unless messages are\n");
    printf("   authenticated (e.g., using digital signatures in Station-to-Station / TLS).\n");
    printf("====================================================================\n");

    return 0;
}
