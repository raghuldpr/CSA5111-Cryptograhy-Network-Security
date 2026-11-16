/*
 * ============================================================================
 * Experiment 25: RSA Common Factor Attack
 * 
 * Objective:
 *   Demonstrate how a known plaintext block sharing a common factor with the
 *   RSA modulus n allows an attacker to compute gcd(M, n), factorize n into
 *   p and q, compute phi(n), derive the private key d, and decrypt intercepted
 *   ciphertext blocks.
 * 
 * Mathematical Attack Mechanism:
 *   1. Let n = p * q be the public RSA modulus.
 *   2. Suppose an attacker discovers or suspects that a known plaintext block M
 *      shares a nontrivial factor with n:
 *         gcd(M, n) = p, where 1 < p < n
 *   3. The attacker computes q = n / p.
 *   4. With p and q known, the attacker calculates:
 *         phi(n) = (p - 1) * (q - 1)
 *   5. The attacker recovers the private key exponent d:
 *         d = e^(-1) mod phi(n)  [via Extended Euclidean Algorithm]
 *   6. Using d, the attacker can decrypt any intercepted ciphertext C:
 *         M_decrypted = (C^d) mod n
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>

// Euclidean algorithm to compute Greatest Common Divisor
long long gcd_euclid(long long a, long long b) {
    while (b != 0) {
        long long temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

// Extended Euclidean Algorithm: a*x + b*y = gcd(a, b)
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

// Computes modular inverse: (e * d) mod m == 1
long long mod_inverse(long long e, long long m) {
    long long x, y;
    long long gcd = extended_gcd(e, m, &x, &y);
    if (gcd != 1) return -1;
    return (x % m + m) % m;
}

// Modular exponentiation using Repeated Squaring (Square-and-Multiply)
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
    long long n, e, M_known, C_intercepted;
    long long p, q, phi_n, d;

    printf("====================================================================\n");
    printf("   EXP 25: RSA COMMON FACTOR ATTACK DEMONSTRATION                   \n");
    printf("====================================================================\n\n");

    // 1. Inputs
    printf("Enter RSA modulus n          (e.g., 3599): ");
    if (scanf("%lld", &n) != 1 || n <= 3) {
        printf("Error: Invalid modulus n.\n");
        return 1;
    }

    printf("Enter public exponent e      (e.g., 31)  : ");
    if (scanf("%lld", &e) != 1 || e <= 1) {
        printf("Error: Invalid exponent e.\n");
        return 1;
    }

    printf("Enter known plaintext block M (e.g., 59)  : ");
    if (scanf("%lld", &M_known) != 1 || M_known <= 0) {
        printf("Error: Invalid known plaintext block M.\n");
        return 1;
    }

    // 2. Compute gcd(M, n)
    long long g = gcd_euclid(M_known, n);
    printf("\n--------------------------------------------------------------------\n");
    printf("STEP 1: COMPUTING GCD(M, n) USING EUCLID'S ALGORITHM\n");
    printf("--------------------------------------------------------------------\n");
    printf("M = %lld, n = %lld\n", M_known, n);
    printf("Calculated gcd(M, n) = %lld\n", g);

    // 3. Evaluate GCD result
    if (g == 1) {
        printf("\n[RESULT] gcd(M, n) = 1 (Trivial factor).\n");
        printf("The known message block M does not share a nontrivial factor with n.\n");
        printf("Direct common factor factorization attack failed.\n");
        return 0;
    } else if (g == n) {
        printf("\n[RESULT] gcd(M, n) = n.\n");
        printf("The known block M is a multiple of n (Trivial case).\n");
        return 0;
    }

    // Nontrivial factor found!
    p = g;
    q = n / p;
    phi_n = (p - 1) * (q - 1);

    printf("\n[SUCCESS] Nontrivial factor found!\n");
    printf("Prime factor p = gcd(M, n) = %lld\n", p);
    printf("Prime factor q = n / p      = %lld / %lld = %lld\n", n, p, q);
    printf("Totient phi(n) = (p-1)*(q-1)= %lld * %lld = %lld\n", p - 1, q - 1, phi_n);

    // 4. Recover private key d
    d = mod_inverse(e, phi_n);
    if (d == -1) {
        printf("Error: Could not compute modular inverse of e mod phi(n).\n");
        return 1;
    }

    printf("\n--------------------------------------------------------------------\n");
    printf("STEP 2: RECOVERING PRIVATE KEY USING EXTENDED EUCLIDEAN ALGORITHM\n");
    printf("--------------------------------------------------------------------\n");
    printf("Formula: d = e^(-1) mod phi(n)\n");
    printf("Recovered Private Key d = %lld\n", d);
    printf("Verification: (%lld * %lld) mod %lld = %lld\n", 
           e, d, phi_n, (long long)(((__int128)e * d) % phi_n));

    // 5. Intercept and decrypt ciphertext
    printf("\n--------------------------------------------------------------------\n");
    printf("STEP 3: DECRYPTING INTERCEPTED CIPHERTEXT BLOCK\n");
    printf("--------------------------------------------------------------------\n");
    printf("Enter intercepted ciphertext block C (e.g., 2383): ");
    if (scanf("%lld", &C_intercepted) != 1 || C_intercepted < 0 || C_intercepted >= n) {
        printf("Error: Invalid ciphertext block.\n");
        return 1;
    }

    long long decrypted_plaintext = mod_exp(C_intercepted, d, n);
    printf("Formula             : M = (C^d) mod n = (%lld^%lld) mod %lld\n", 
           C_intercepted, d, n);
    printf("Decrypted Plaintext : %lld\n", decrypted_plaintext);

    // 6. Explanation
    printf("\n====================================================================\n");
    printf("SECURITY ANALYSIS & EXPLANATION:\n");
    printf("====================================================================\n");
    printf("1. Vulnerability:\n");
    printf("   If a known or crafted plaintext block M shares a factor with n,\n");
    printf("   gcd(M, n) effortlessly isolates a prime factor in O(log n) steps\n");
    printf("   without having to perform full factorization.\n");
    printf("2. Full Compromise:\n");
    printf("   Once p is recovered, q = n / p and phi(n) = (p - 1)(q - 1) follow\n");
    printf("   immediately. The attacker computes d = e^(-1) mod phi(n) and breaks\n");
    printf("   the entire cryptosystem for all subsequent messages.\n");
    printf("3. Countermeasure:\n");
    printf("   Use large primes (e.g., 2048-bit or 4096-bit RSA) and proper padding\n");
    printf("   schemes like OAEP so that plaintext blocks never equal or share\n");
    printf("   algebraic factors with the modulus.\n");
    printf("====================================================================\n");

    return 0;
}
