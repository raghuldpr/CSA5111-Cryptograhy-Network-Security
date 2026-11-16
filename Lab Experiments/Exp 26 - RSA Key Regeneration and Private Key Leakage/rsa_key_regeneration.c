/*
 * ============================================================================
 * Experiment 26: RSA Key Regeneration and Private Key Leakage
 * 
 * Objective:
 *   Demonstrate RSA key regeneration when a private key is leaked, and explain
 *   why changing only the public/private exponents while keeping the same
 *   modulus n provides NO security against an attacker.
 * 
 * Cryptographic Principles:
 *   1. Initial Setup:
 *      Modulus n = p * q
 *      Totient phi(n) = (p - 1) * (q - 1)
 *      Old Public Key: (e_old, n)
 *      Old Private Key: (d_old, n), where e_old * d_old = 1 (mod phi(n))
 * 
 *   2. Flawed Remediation:
 *      If d_old is compromised, Bob attempts to recover by choosing a new
 *      public exponent e_new and computing d_new = e_new^(-1) mod phi(n),
 *      keeping n unchanged.
 * 
 *   3. Why This Fails:
 *      An attacker who obtained (e_old, d_old, n) can factor n or compute phi(n).
 *      Knowing phi(n) allows the attacker to immediately compute:
 *         d_new = (e_new)^(-1) mod phi(n)
 *      as soon as Bob publishes the new public exponent e_new!
 *      Therefore, Bob MUST generate fresh primes p' and q' and a new modulus n'.
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>

// Extended Euclidean Algorithm
long long extended_gcd(long long a, long long b, long long *x, long long *y) {
    if (b == 0) {
        *x = 1;
        *y = 0;
        return a;
    }
    long long x1, y1;
    long long gcd = extended_gcd(b, a % b, &x1, &y1);
    *x = y1;
    *y = x1 - (a / b) * y1;
    return gcd;
}

// Modular inverse: finds d such that (e * d) mod m == 1
long long mod_inverse(long long e, long long m) {
    long long x, y;
    long long gcd = extended_gcd(e, m, &x, &y);
    if (gcd != 1) return -1;
    return (x % m + m) % m;
}

int main(void) {
    long long p, q, n, phi_n;
    long long e_old, d_old;
    long long e_new, d_new;

    printf("====================================================================\n");
    printf("   EXP 26: RSA KEY REGENERATION & PRIVATE KEY LEAKAGE ANALYSIS     \n");
    printf("====================================================================\n\n");

    // 1. Accept prime numbers p and q
    printf("Enter prime number p                (e.g., 59): ");
    if (scanf("%lld", &p) != 1 || p <= 1) {
        printf("Error: Invalid prime number p.\n");
        return 1;
    }

    printf("Enter prime number q                (e.g., 61): ");
    if (scanf("%lld", &q) != 1 || q <= 1 || p == q) {
        printf("Error: Invalid prime number q (must be distinct from p).\n");
        return 1;
    }

    // 2. Compute modulus and totient
    n = p * q;
    phi_n = (p - 1) * (q - 1);

    printf("\n--> Modulus Setup:\n");
    printf("    Modulus n = p * q = %lld * %lld = %lld\n", p, q, n);
    printf("    Totient phi(n)    = (%lld - 1) * (%lld - 1) = %lld\n", p, q, phi_n);

    // 3. Accept Old Public Exponent
    printf("\nEnter Old Public Exponent e_old      (e.g., 31): ");
    if (scanf("%lld", &e_old) != 1 || e_old <= 1) {
        printf("Error: Invalid old public exponent.\n");
        return 1;
    }

    d_old = mod_inverse(e_old, phi_n);
    if (d_old == -1) {
        printf("Error: gcd(e_old, phi(n)) != 1. Modular inverse does not exist.\n");
        return 1;
    }

    // 4. Accept New Public Exponent
    printf("Enter New Public Exponent e_new      (e.g., 7) : ");
    if (scanf("%lld", &e_new) != 1 || e_new <= 1) {
        printf("Error: Invalid new public exponent.\n");
        return 1;
    }

    d_new = mod_inverse(e_new, phi_n);
    if (d_new == -1) {
        printf("Error: gcd(e_new, phi(n)) != 1. Modular inverse does not exist.\n");
        return 1;
    }

    // 5. Display Key Pairs
    printf("\n--------------------------------------------------------------------\n");
    printf("1. ORIGINAL (COMPROMISED) KEY PAIR:\n");
    printf("--------------------------------------------------------------------\n");
    printf("Modulus n                  : %lld\n", n);
    printf("Euler Totient phi(n)       : %lld\n", phi_n);
    printf("Old Public Exponent e_old  : %lld\n", e_old);
    printf("Old Private Exponent d_old : %lld\n", d_old);
    printf("Old Public Key             : (e = %lld, n = %lld)\n", e_old, n);
    printf("Old Private Key            : (d = %lld, n = %lld)\n", d_old, n);
    printf("Verification               : (%lld * %lld) mod %lld = %lld\n",
           e_old, d_old, phi_n, (long long)(((__int128)e_old * d_old) % phi_n));

    printf("\n--------------------------------------------------------------------\n");
    printf("2. REGENERATED KEY PAIR (SAME MODULUS n):\n");
    printf("--------------------------------------------------------------------\n");
    printf("Modulus n (Unchanged)      : %lld\n", n);
    printf("Euler Totient phi(n)       : %lld\n", phi_n);
    printf("New Public Exponent e_new  : %lld\n", e_new);
    printf("New Private Exponent d_new : %lld\n", d_new);
    printf("New Public Key             : (e = %lld, n = %lld)\n", e_new, n);
    printf("New Private Key            : (d = %lld, n = %lld)\n", d_new, n);
    printf("Verification               : (%lld * %lld) mod %lld = %lld\n",
           e_new, d_new, phi_n, (long long)(((__int128)e_new * d_new) % phi_n));

    // 6. Security Analysis & Demonstration
    printf("\n====================================================================\n");
    printf("SECURITY ANALYSIS: WHY CHANGING ONLY THE EXPONENTS FAILS\n");
    printf("====================================================================\n");
    printf("1. The Compromise:\n");
    printf("   Suppose Bob's private key d_old = %lld was leaked to Eve.\n", d_old);
    printf("   Eve now knows:\n");
    printf("     e_old = %lld, d_old = %lld, and n = %lld\n", e_old, d_old, n);
    printf("\n2. Factorization of Modulus n from Leaked Key:\n");
    printf("   Since e_old * d_old - 1 = (%lld * %lld) - 1 = %lld,\n", 
           e_old, d_old, e_old * d_old - 1);
    printf("   which is a multiple of phi(n) = %lld (%lld * %lld),\n", 
           phi_n, (e_old * d_old - 1) / phi_n, phi_n);
    printf("   an attacker can factor n into p = %lld and q = %lld.\n", p, q);
    printf("\n3. Immediate Recovery of Any New Private Key:\n");
    printf("   When Bob publishes a new public exponent e_new = %lld while\n", e_new);
    printf("   reusing the same modulus n = %lld:\n", n);
    printf("   Eve simply computes:\n");
    printf("     d_new = (e_new)^(-1) mod phi(n) = (%lld)^(-1) mod %lld = %lld\n",
           e_new, phi_n, d_new);
    printf("   Eve recalculates the private key with ZERO effort!\n");
    printf("\n4. Proper Cryptographic Resolution:\n");
    printf("   Once a private key is leaked, the modulus n is permanently burned.\n");
    printf("   Bob MUST generate completely NEW, independent primes p' and q',\n");
    printf("   forming a new modulus n' = p' * q', and discard the old modulus.\n");
    printf("====================================================================\n");

    return 0;
}
