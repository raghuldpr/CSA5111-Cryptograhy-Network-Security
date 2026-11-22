/*
 * ============================================================================
 * Experiment 36: Affine Caesar Cipher Implementation & Key Validation
 *
 * Objective:
 *   Implement encryption and decryption for the Affine Caesar Cipher.
 *   Validate that key 'a' must be coprime to 26 (gcd(a, 26) == 1) for a valid
 *   decryption inverse to exist. Demonstrate why the cipher is not one-to-one
 *   when gcd(a, 26) != 1 using the required test case a = 2, b = 3.
 *
 * Mathematical Foundations:
 *   Encryption Formula:
 *     C = (a * P + b) mod 26
 *
 *   Decryption Formula:
 *     P = a^(-1) * (C - b) mod 26
 *
 * Coprimality Condition:
 *   The multiplier 'a' has a modular multiplicative inverse modulo 26 if and
 *   only if gcd(a, 26) = 1.
 *   The valid values of 'a' in Z_26 are:
 *     {1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25} (Euler's totient phi(26) = 12).
 *
 * Collision Demonstration (a = 2, b = 3):
 *   Since gcd(2, 26) = 2 != 1, 'a' shares a common factor with 26.
 *   - For P = 0  ('A'): E(0)  = (2 * 0 + 3) mod 26  = 3  ('D')
 *   - For P = 13 ('N'): E(13) = (2 * 13 + 3) mod 26 = 29 mod 26 = 3 ('D')
 *   Since P = 0 and P = 13 both map to ciphertext 3 ('D'), the function is
 *   NOT injective (not one-to-one). Decrypting 'D' is mathematically ambiguous.
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_TEXT_LEN 1024

// Computes greatest common divisor
int gcd(int a, int b) {
    while (b != 0) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

// Computes modular inverse using Extended Euclidean Algorithm
// Returns -1 if no modular inverse exists (gcd != 1)
int mod_inverse(int a, int m) {
    int m0 = m;
    int y = 0, x = 1;

    if (gcd(a, m) != 1) return -1;
    if (m == 1) return 0;

    a = (a % m + m) % m;

    while (a > 1) {
        int q = a / m;
        int t = m;
        m = a % m;
        a = t;
        t = y;
        y = x - q * y;
        x = t;
    }

    if (x < 0) x += m0;
    return x;
}

// Demonstrates why gcd(a, 26) != 1 fails to be one-to-one (bijection)
void demonstrate_invalid_key_collision(void) {
    int a = 2, b = 3;
    printf("--------------------------------------------------------------------\n");
    printf("         REQUIRED DEMONSTRATION: COLLISION TEST (a = 2, b = 3)      \n");
    printf("--------------------------------------------------------------------\n");
    printf("Testing with keys: a = %d, b = %d\n", a, b);
    printf("GCD(a, 26) = GCD(%d, 26) = %d\n", a, gcd(a, 26));
    printf("Status: GCD != 1, so modular inverse a^(-1) mod 26 DOES NOT EXIST.\n\n");

    int p1 = 0;  // 'A'
    int p2 = 13; // 'N'
    int c1 = (a * p1 + b) % 26;
    int c2 = (a * p2 + b) % 26;

    printf("Evaluating Plaintext Values:\n");
    printf("  Plaintext P =  0 ('A') -> E(0)  = (%d *  0 + %d) mod 26 = %2d ('%c')\n",
           a, b, c1, 'A' + c1);
    printf("  Plaintext P = 13 ('N') -> E(13) = (%d * 13 + %d) mod 26 = %2d mod 26 = %2d ('%c')\n",
           a, b, a * p2 + b, c2, 'A' + c2);

    printf("\nConclusion:\n");
    printf("  Both P = 0 ('A') and P = 13 ('N') produce the identical ciphertext '%c' (3).\n", 'A' + c1);
    printf("  Because the encryption mapping is NOT one-to-one (not a bijection),\n");
    printf("  reversing the operation is mathematically ambiguous. Therefore, a valid\n");
    printf("  Affine Cipher key REQUIRES gcd(a, 26) == 1.\n");
    printf("--------------------------------------------------------------------\n\n");
}

int main(void) {
    char plaintext[MAX_TEXT_LEN];
    char ciphertext[MAX_TEXT_LEN];
    char decrypted[MAX_TEXT_LEN];
    int a, b;
    int a_inv;

    printf("====================================================================\n");
    printf("             EXPERIMENT 36: AFFINE CAESAR CIPHER                    \n");
    printf("====================================================================\n\n");

    // 1. Run the required demonstration first
    demonstrate_invalid_key_collision();

    // 2. Interactive Section
    printf("Enter Plaintext string:\n> ");
    if (fgets(plaintext, sizeof(plaintext), stdin) == NULL) {
        printf("[ERROR] Failed to read plaintext.\n");
        return 1;
    }
    plaintext[strcspn(plaintext, "\r\n")] = '\0';

    printf("Enter key 'a' (multiplicative key) [must satisfy gcd(a, 26) == 1]: ");
    if (scanf("%d", &a) != 1) {
        printf("[ERROR] Invalid key 'a'.\n");
        return 1;
    }

    printf("Enter key 'b' (additive shift key, 0 - 25): ");
    if (scanf("%d", &b) != 1) {
        printf("[ERROR] Invalid key 'b'.\n");
        return 1;
    }

    b = (b % 26 + 26) % 26;
    int g = gcd(a, 26);
    printf("\n[*] Validating Key: gcd(%d, 26) = %d\n", a, g);

    if (g != 1) {
        printf("[ERROR] Key a = %d is INVALID for decryption!\n", a);
        printf("        gcd(%d, 26) = %d != 1. Modular inverse does not exist.\n", a, g);
        printf("        Valid values for 'a' are: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25.\n");
        return 1;
    }

    a_inv = mod_inverse(a, 26);
    printf("[*] Key 'a' is valid. Modular Inverse a^(-1) mod 26 = %d (since %d * %d = %d = 1 mod 26)\n",
           a_inv, a, a_inv, a * a_inv);

    // 3. Encrypt Plaintext
    int len = strlen(plaintext);
    for (int i = 0; i < len; i++) {
        char ch = plaintext[i];
        if (isupper(ch)) {
            int p = ch - 'A';
            int c = (a * p + b) % 26;
            ciphertext[i] = (char)(c + 'A');
        } else if (islower(ch)) {
            int p = ch - 'a';
            int c = (a * p + b) % 26;
            ciphertext[i] = (char)(c + 'a');
        } else {
            ciphertext[i] = ch;
        }
    }
    ciphertext[len] = '\0';

    // 4. Decrypt Ciphertext
    for (int i = 0; i < len; i++) {
        char ch = ciphertext[i];
        if (isupper(ch)) {
            int c = ch - 'A';
            int p = (a_inv * (c - b + 26)) % 26;
            decrypted[i] = (char)(p + 'A');
        } else if (islower(ch)) {
            int c = ch - 'a';
            int p = (a_inv * (c - b + 26)) % 26;
            decrypted[i] = (char)(p + 'a');
        } else {
            decrypted[i] = ch;
        }
    }
    decrypted[len] = '\0';

    // 5. Results
    printf("\n====================================================================\n");
    printf("                    AFFINE CIPHER RESULTS                           \n");
    printf("====================================================================\n");
    printf("Keys Used                 : a = %d, b = %d (a_inv = %d)\n", a, b, a_inv);
    printf("Encryption Formula        : C = (%d * P + %d) mod 26\n", a, b);
    printf("Decryption Formula        : P = %d * (C - %d) mod 26\n", a_inv, b);
    printf("Original Plaintext        : %s\n", plaintext);
    printf("Encrypted Ciphertext      : %s\n", ciphertext);
    printf("Decrypted Plaintext       : %s\n", decrypted);
    printf("====================================================================\n");

    if (strcmp(plaintext, decrypted) == 0) {
        printf("[SUCCESS] Original plaintext recovered successfully!\n");
    } else {
        printf("[ERROR] Decryption mismatch.\n");
    }

    return 0;
}
