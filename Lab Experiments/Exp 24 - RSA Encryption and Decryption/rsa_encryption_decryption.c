/*
 * ============================================================================
 * Experiment 24: RSA Encryption and Decryption
 * 
 * Objective:
 *   Implement RSA key generation, factorization via trial division,
 *   Extended Euclidean Algorithm for private exponent derivation,
 *   modular exponentiation via repeated squaring, and encryption/decryption.
 * 
 * Mathematical Formulation:
 *   1. Key Setup:
 *      n = p * q
 *      phi(n) = (p - 1) * (q - 1)
 *      Public Key  = (e, n)
 *      Private Key = (d, n), where e * d = 1 (mod phi(n))
 * 
 *   2. Encryption:
 *      C = (M^e) mod n
 * 
 *   3. Decryption:
 *      M = (C^d) mod n
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>

// Extended Euclidean Algorithm: computes gcd(a, b) and bezout coefficients x, y
// such that a*x + b*y = gcd(a, b).
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
    if (gcd != 1) {
        return -1; // Modular inverse does not exist
    }
    long long d = (x % m + m) % m;
    return d;
}

// Modular exponentiation using Repeated Squaring (Square-and-Multiply)
// Computes (base^exp) mod mod
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

// Factorizes n into p and q using trial division
int factorize_modulus(long long n, long long *p, long long *q) {
    for (long long d = 2; d * d <= n; d++) {
        if (n % d == 0) {
            *p = d;
            *q = n / d;
            return 1;
        }
    }
    return 0; // Prime or prime square not found
}

int main(void) {
    long long e, n;
    long long p = 0, q = 0;
    long long phi_n;
    long long d;
    long long plaintext, ciphertext, decrypted_pt;

    printf("====================================================================\n");
    printf("   EXP 24: RSA KEY GENERATION, ENCRYPTION & DECRYPTION             \n");
    printf("====================================================================\n\n");

    // 1. Accept public exponent e and modulus n
    printf("Enter public exponent e (e.g., 31)  : ");
    if (scanf("%lld", &e) != 1 || e <= 1) {
        printf("Error: Invalid public exponent e.\n");
        return 1;
    }

    printf("Enter RSA modulus n     (e.g., 3599): ");
    if (scanf("%lld", &n) != 1 || n <= 3) {
        printf("Error: Invalid modulus n.\n");
        return 1;
    }

    // 2. Factorize n to find p and q via trial division
    printf("\n--> Factorizing n = %lld via trial division...\n", n);
    if (!factorize_modulus(n, &p, &q)) {
        printf("Error: Could not factorize n into distinct primes.\n");
        return 1;
    }

    phi_n = (p - 1) * (q - 1);
    printf("    Found prime factor p = %lld\n", p);
    printf("    Found prime factor q = %lld\n", q);
    printf("    Euler totient phi(n) = (p-1)*(q-1) = %lld * %lld = %lld\n", 
           p - 1, q - 1, phi_n);

    // 3. Compute private exponent d using Extended Euclidean Algorithm
    d = mod_inverse(e, phi_n);
    if (d == -1) {
        printf("Error: e and phi(n) are not coprime. No modular inverse exists.\n");
        return 1;
    }

    printf("\n--> Computing Private Exponent d using Extended Euclidean Algorithm:\n");
    printf("    Formula: (e * d) mod phi(n) = 1\n");
    printf("    Derived Private Exponent d = %lld\n", d);
    printf("    Verification: (%lld * %lld) mod %lld = %lld\n", 
           e, d, phi_n, (long long)(((__int128)e * d) % phi_n));

    printf("\n--------------------------------------------------------------------\n");
    printf("RSA KEY PAIRS:\n");
    printf("--------------------------------------------------------------------\n");
    printf("Public Key  (e, n) : (%lld, %lld)\n", e, n);
    printf("Private Key (d, n) : (%lld, %lld)\n", d, n);

    // 4. Accept plaintext integer to encrypt
    printf("\nEnter plaintext integer M (0 <= M < %lld) (e.g., 65): ", n);
    if (scanf("%lld", &plaintext) != 1 || plaintext < 0 || plaintext >= n) {
        printf("Error: Plaintext integer M must satisfy 0 <= M < %lld.\n", n);
        return 1;
    }

    // 5. Encrypt using modular exponentiation
    ciphertext = mod_exp(plaintext, e, n);
    printf("\n--------------------------------------------------------------------\n");
    printf("ENCRYPTION PROCESS:\n");
    printf("--------------------------------------------------------------------\n");
    printf("Plaintext M        : %lld\n", plaintext);
    printf("Formula            : C = (M^e) mod n = (%lld^%lld) mod %lld\n", plaintext, e, n);
    printf("Ciphertext C       : %lld\n", ciphertext);

    // 6. Decrypt using modular exponentiation
    decrypted_pt = mod_exp(ciphertext, d, n);
    printf("\n--------------------------------------------------------------------\n");
    printf("DECRYPTION PROCESS:\n");
    printf("--------------------------------------------------------------------\n");
    printf("Ciphertext C       : %lld\n", ciphertext);
    printf("Formula            : M = (C^d) mod n = (%lld^%lld) mod %lld\n", ciphertext, d, n);
    printf("Decrypted Plaintext: %lld\n", decrypted_pt);

    // 7. Verification
    printf("\n====================================================================\n");
    printf("VERIFICATION SUMMARY:\n");
    printf("====================================================================\n");
    if (decrypted_pt == plaintext) {
        printf("[SUCCESS] Decrypted message (%lld) matches original plaintext (%lld)!\n", 
               decrypted_pt, plaintext);
    } else {
        printf("[FAILED] Plaintext mismatch! Encryption/Decryption failed.\n");
    }
    printf("====================================================================\n");

    return 0;
}
