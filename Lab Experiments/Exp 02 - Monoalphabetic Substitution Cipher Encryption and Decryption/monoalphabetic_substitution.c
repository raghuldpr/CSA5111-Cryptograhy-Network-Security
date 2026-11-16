/*
 * Experiment 2: Monoalphabetic Substitution Cipher Encryption and Decryption
 * 
 * Mathematical Formulation:
 * A monoalphabetic substitution cipher maps each letter of the 26-character
 * plaintext alphabet P = {A..Z} to a unique permutation K = {k_0, k_1, ..., k_25}.
 * 
 * Encryption: C_i = K[P_i - 'A']
 * Decryption: P_i = K^{-1}[C_i - 'A']
 * 
 * Key Validation:
 * The key must be exactly 26 alphabetic characters with no duplicates (bijection).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define ALPHABET_LEN 26
#define MAX_LEN 1024

// Validates that key has length 26 and contains every letter A-Z exactly once
int validate_key(const char *key, char *clean_key) {
    int len = (int)strlen(key);
    int seen[ALPHABET_LEN] = {0};
    int count = 0;

    for (int i = 0; i < len; i++) {
        if (isalpha((unsigned char)key[i])) {
            char upper = (char)toupper((unsigned char)key[i]);
            int idx = upper - 'A';
            if (seen[idx]) {
                printf("[!] Error: Duplicate letter '%c' found in key.\n", upper);
                return 0; // Duplicate detected
            }
            seen[idx] = 1;
            clean_key[count++] = upper;
        }
    }
    clean_key[count] = '\0';

    if (count != ALPHABET_LEN) {
        printf("[!] Error: Key must contain all 26 alphabetic letters (found %d).\n", count);
        return 0;
    }
    return 1;
}

// Builds inverse substitution map for fast decryption
void build_decrypt_map(const char *key, char *inv_map) {
    for (int i = 0; i < ALPHABET_LEN; i++) {
        int cipher_idx = key[i] - 'A';
        inv_map[cipher_idx] = (char)('A' + i);
    }
    inv_map[ALPHABET_LEN] = '\0';
}

// Encrypts plaintext using substitution key
void mono_encrypt(const char *plaintext, const char *key, char *ciphertext) {
    int len = (int)strlen(plaintext);
    for (int i = 0; i < len; i++) {
        char ch = plaintext[i];
        if (isupper((unsigned char)ch)) {
            ciphertext[i] = key[ch - 'A'];
        } else if (islower((unsigned char)ch)) {
            ciphertext[i] = (char)tolower((unsigned char)key[ch - 'a']);
        } else {
            ciphertext[i] = ch;
        }
    }
    ciphertext[len] = '\0';
}

// Decrypts ciphertext using inverse key map
void mono_decrypt(const char *ciphertext, const char *inv_map, char *plaintext) {
    int len = (int)strlen(ciphertext);
    for (int i = 0; i < len; i++) {
        char ch = ciphertext[i];
        if (isupper((unsigned char)ch)) {
            plaintext[i] = inv_map[ch - 'A'];
        } else if (islower((unsigned char)ch)) {
            plaintext[i] = (char)tolower((unsigned char)inv_map[ch - 'a']);
        } else {
            plaintext[i] = ch;
        }
    }
    plaintext[len] = '\0';
}

int main(void) {
    char raw_key[MAX_LEN];
    char clean_key[ALPHABET_LEN + 1];
    char inv_map[ALPHABET_LEN + 1];
    char plaintext[MAX_LEN];
    char ciphertext[MAX_LEN];
    char decrypted[MAX_LEN];

    printf("=================================================================\n");
    printf(" EXPERIMENT 2: MONOALPHABETIC SUBSTITUTION CIPHER (ENCRYPT/DECRYPT)\n");
    printf("=================================================================\n\n");

    printf("Enter 26-letter substitution key alphabet: ");
    if (fgets(raw_key, sizeof(raw_key), stdin) == NULL || strlen(raw_key) <= 1) {
        // Standard sample permutation
        strcpy(raw_key, "QWERTYUIOPASDFGHJKLZXCVBNM");
        printf("%s\n", raw_key);
    } else {
        raw_key[strcspn(raw_key, "\r\n")] = '\0';
    }

    if (!validate_key(raw_key, clean_key)) {
        printf("\nUsing default valid key: QWERTYUIOPASDFGHJKLZXCVBNM\n");
        strcpy(clean_key, "QWERTYUIOPASDFGHJKLZXCVBNM");
    }

    build_decrypt_map(clean_key, inv_map);

    printf("Enter plaintext: ");
    if (fgets(plaintext, sizeof(plaintext), stdin) == NULL || strlen(plaintext) <= 1) {
        strcpy(plaintext, "Defend the east wall at dawn");
        printf("%s\n", plaintext);
    } else {
        plaintext[strcspn(plaintext, "\r\n")] = '\0';
    }

    mono_encrypt(plaintext, clean_key, ciphertext);
    mono_decrypt(ciphertext, inv_map, decrypted);

    printf("\n-----------------------------------------------------------------\n");
    printf("SUBSTITUTION MAPPING TABLE:\n");
    printf("-----------------------------------------------------------------\n");
    printf("Plain  : ABCDEFGHIJKLMNOPQRSTUVWXYZ\n");
    printf("Cipher : %s\n", clean_key);

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
