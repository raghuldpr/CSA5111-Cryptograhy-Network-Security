/*
 * Experiment 1: Caesar Cipher Encryption and Decryption Using C
 * 
 * Mathematical Formulation:
 * Encryption: C_i = (P_i + K) mod 26
 * Decryption: P_i = (C_i - K + 26) mod 26
 * where:
 *   P_i = numerical value of plaintext character (A=0, ..., Z=25)
 *   C_i = numerical value of ciphertext character (A=0, ..., Z=25)
 *   K   = shift key (integer)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_LEN 1024

// Normalizes shift key to range [0, 25]
int normalize_key(int key) {
    int mod = key % 26;
    if (mod < 0) {
        mod += 26;
    }
    return mod;
}

// Encrypts plaintext using Caesar cipher with given shift key
void caesar_encrypt(const char *plaintext, int key, char *ciphertext) {
    int shift = normalize_key(key);
    int len = (int)strlen(plaintext);

    for (int i = 0; i < len; i++) {
        char ch = plaintext[i];
        if (isupper((unsigned char)ch)) {
            ciphertext[i] = (char)(((ch - 'A' + shift) % 26) + 'A');
        } else if (islower((unsigned char)ch)) {
            ciphertext[i] = (char)(((ch - 'a' + shift) % 26) + 'a');
        } else {
            ciphertext[i] = ch; // Non-alphabetic characters remain unchanged
        }
    }
    ciphertext[len] = '\0';
}

// Decrypts ciphertext using Caesar cipher with given shift key
void caesar_decrypt(const char *ciphertext, int key, char *plaintext) {
    int shift = normalize_key(key);
    int len = (int)strlen(ciphertext);

    for (int i = 0; i < len; i++) {
        char ch = ciphertext[i];
        if (isupper((unsigned char)ch)) {
            plaintext[i] = (char)(((ch - 'A' - shift + 26) % 26) + 'A');
        } else if (islower((unsigned char)ch)) {
            plaintext[i] = (char)(((ch - 'a' - shift + 26) % 26) + 'a');
        } else {
            plaintext[i] = ch; // Non-alphabetic characters remain unchanged
        }
    }
    plaintext[len] = '\0';
}

int main(void) {
    char plaintext[MAX_LEN];
    char ciphertext[MAX_LEN];
    char decrypted[MAX_LEN];
    int key;

    printf("=================================================================\n");
    printf("  EXPERIMENT 1: CAESAR CIPHER ENCRYPTION AND DECRYPTION USING C  \n");
    printf("=================================================================\n\n");

    printf("Enter plaintext message: ");
    if (fgets(plaintext, sizeof(plaintext), stdin) == NULL) {
        strcpy(plaintext, "Cryptography and Network Security");
        printf("%s\n", plaintext);
    } else {
        // Remove trailing newline character
        plaintext[strcspn(plaintext, "\r\n")] = '\0';
        if (strlen(plaintext) == 0) {
            strcpy(plaintext, "Cryptography and Network Security");
        }
    }

    printf("Enter shift key (integer, e.g., 3): ");
    if (scanf("%d", &key) != 1) {
        key = 3;
        printf("3 (default)\n");
    }

    int norm_key = normalize_key(key);

    caesar_encrypt(plaintext, norm_key, ciphertext);
    caesar_decrypt(ciphertext, norm_key, decrypted);

    printf("\n-----------------------------------------------------------------\n");
    printf("RESULTS & VERIFICATION:\n");
    printf("-----------------------------------------------------------------\n");
    printf("Original Plaintext  : %s\n", plaintext);
    printf("Shift Key Applied   : %d (Effective shift: %d)\n", key, norm_key);
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
