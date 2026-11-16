/*
 * Experiment 5: Affine Caesar Cipher
 * 
 * Mathematical Formulation:
 * Encryption: C = (a * P + b) mod 26
 * Decryption: P = a^{-1} * (C - b) mod 26
 * where:
 *   a = multiplicative key, must satisfy gcd(a, 26) = 1
 *   b = additive key (shift), 0 <= b < 26
 *   a^{-1} = modular multiplicative inverse of a modulo 26, such that (a * a^{-1}) mod 26 = 1
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_LEN 1024

// Computes greatest common divisor
int gcd(int a, int b) {
    while (b != 0) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

// Computes modular multiplicative inverse of 'a' modulo 'm' using Extended Euclidean Algorithm
int mod_inverse(int a, int m) {
    a = (a % m + m) % m;
    int m0 = m, t, q;
    int x0 = 0, x1 = 1;

    if (m == 1) return 0;

    while (a > 1) {
        if (m == 0) return -1; // Inverse does not exist
        q = a / m;
        t = m;
        m = a % m;
        a = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }

    if (x1 < 0) x1 += m0;
    return x1;
}

// Affine encryption function
void affine_encrypt(const char *plaintext, int a, int b, char *ciphertext) {
    int len = (int)strlen(plaintext);
    for (int i = 0; i < len; i++) {
        char ch = plaintext[i];
        if (isupper((unsigned char)ch)) {
            int p = ch - 'A';
            int c = (a * p + b) % 26;
            ciphertext[i] = (char)(c + 'A');
        } else if (islower((unsigned char)ch)) {
            int p = ch - 'a';
            int c = (a * p + b) % 26;
            ciphertext[i] = (char)(c + 'a');
        } else {
            ciphertext[i] = ch;
        }
    }
    ciphertext[len] = '\0';
}

// Affine decryption function
void affine_decrypt(const char *ciphertext, int a_inv, int b, char *plaintext) {
    int len = (int)strlen(ciphertext);
    for (int i = 0; i < len; i++) {
        char ch = ciphertext[i];
        if (isupper((unsigned char)ch)) {
            int c = ch - 'A';
            int p = (a_inv * (c - b + 2600)) % 26; // Ensure positive argument
            plaintext[i] = (char)(p + 'A');
        } else if (islower((unsigned char)ch)) {
            int c = ch - 'a';
            int p = (a_inv * (c - b + 2600)) % 26;
            plaintext[i] = (char)(p + 'a');
        } else {
            plaintext[i] = ch;
        }
    }
    plaintext[len] = '\0';
}

int main(void) {
    char plaintext[MAX_LEN];
    char ciphertext[MAX_LEN];
    char decrypted[MAX_LEN];
    int a, b;

    printf("=================================================================\n");
    printf("         EXPERIMENT 5: AFFINE CAESAR CIPHER (C = aP + b mod 26)  \n");
    printf("=================================================================\n\n");

    printf("Enter multiplicative key 'a' (must be coprime to 26): ");
    if (scanf("%d", &a) != 1) {
        a = 7;
        printf("7 (default)\n");
    }

    // Validate coprime condition
    if (gcd(a, 26) != 1) {
        printf("[!] ERROR: Key a=%d is NOT coprime to 26 (gcd = %d). Decryption is impossible.\n", a, gcd(a, 26));
        printf("    Allowed values for 'a': 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25.\n");
        printf("    Resetting 'a' to valid default: 7\n");
        a = 7;
    }

    printf("Enter additive shift key 'b' (0-25): ");
    if (scanf("%d", &b) != 1) {
        b = 2;
        printf("2 (default)\n");
    }
    b = (b % 26 + 26) % 26;

    // Clear buffer
    int ch;
    while ((ch = getchar()) != '\n' && ch != EOF);

    printf("Enter plaintext: ");
    if (fgets(plaintext, sizeof(plaintext), stdin) == NULL || strlen(plaintext) <= 1) {
        strcpy(plaintext, "AFFINE CIPHER IMPLEMENTATION");
        printf("%s\n", plaintext);
    } else {
        plaintext[strcspn(plaintext, "\r\n")] = '\0';
    }

    int a_inv = mod_inverse(a, 26);

    affine_encrypt(plaintext, a, b, ciphertext);
    affine_decrypt(ciphertext, a_inv, b, decrypted);

    printf("\n-----------------------------------------------------------------\n");
    printf("MATHEMATICAL PARAMETERS:\n");
    printf("-----------------------------------------------------------------\n");
    printf("Multiplicative Key (a)     : %d  [gcd(%d, 26) = %d -> VALID]\n", a, a, gcd(a, 26));
    printf("Additive Key (b)           : %d\n", b);
    printf("Modular Inverse of a (a^-1): %d  [(%d * %d) mod 26 = %d]\n", a_inv, a, a_inv, (a * a_inv) % 26);
    printf("Encryption Formula         : C = (%d * P + %d) mod 26\n", a, b);
    printf("Decryption Formula         : P = %d * (C - %d) mod 26\n", a_inv, b);

    printf("\n-----------------------------------------------------------------\n");
    printf("RESULTS & VERIFICATION:\n");
    printf("-----------------------------------------------------------------\n");
    printf("Original Plaintext  : %s\n", plaintext);
    printf("Encrypted Ciphertext: %s\n", ciphertext);
    printf("Decrypted Plaintext : %s\n", decrypted);

    if (strcmp(plaintext, decrypted) == 0) {
        printf("\n[+] Verification SUCCESS: Decrypted text matches original plaintext.\n");
    } else {
        printf("\n[-] Verification FAILED: Decrypted text does not match.\n");
    }
    printf("=================================================================\n");

    return 0;
}
