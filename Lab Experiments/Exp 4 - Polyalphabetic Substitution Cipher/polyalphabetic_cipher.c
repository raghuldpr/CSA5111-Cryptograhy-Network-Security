/*
 * Experiment 4: Polyalphabetic Substitution Cipher (Vigenere Cipher)
 * 
 * Mathematical Formulation:
 * Encryption: C_i = (P_i + K_i) mod 26
 * Decryption: P_i = (C_i - K_i + 26) mod 26
 * where:
 *   P_i is the numerical value (0..25) of the i-th plaintext letter
 *   K_i is the numerical value (0..25) of the repeating keyword letter
 *   C_i is the numerical value (0..25) of the ciphertext letter
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_LEN 2048

// Generates keystream aligned with plaintext alphabetic characters
void generate_keystream(const char *plaintext, const char *keyword, char *keystream) {
    int key_len = (int)strlen(keyword);
    int key_idx = 0;
    int pt_len = (int)strlen(plaintext);

    for (int i = 0; i < pt_len; i++) {
        if (isalpha((unsigned char)plaintext[i])) {
            char k = keyword[key_idx % key_len];
            keystream[i] = isupper((unsigned char)plaintext[i]) ? (char)toupper((unsigned char)k) : (char)tolower((unsigned char)k);
            key_idx++;
        } else {
            keystream[i] = plaintext[i]; // Non-alpha characters keep same alignment
        }
    }
    keystream[pt_len] = '\0';
}

// Polyalphabetic Encryption
void vigenere_encrypt(const char *plaintext, const char *keystream, char *ciphertext) {
    int len = (int)strlen(plaintext);
    for (int i = 0; i < len; i++) {
        char p = plaintext[i];
        char k = keystream[i];
        if (isupper((unsigned char)p)) {
            ciphertext[i] = (char)(((p - 'A' + (toupper((unsigned char)k) - 'A')) % 26) + 'A');
        } else if (islower((unsigned char)p)) {
            ciphertext[i] = (char)(((p - 'a' + (tolower((unsigned char)k) - 'a')) % 26) + 'a');
        } else {
            ciphertext[i] = p;
        }
    }
    ciphertext[len] = '\0';
}

// Polyalphabetic Decryption
void vigenere_decrypt(const char *ciphertext, const char *keystream, char *plaintext) {
    int len = (int)strlen(ciphertext);
    for (int i = 0; i < len; i++) {
        char c = ciphertext[i];
        char k = keystream[i];
        if (isupper((unsigned char)c)) {
            plaintext[i] = (char)(((c - 'A' - (toupper((unsigned char)k) - 'A') + 26) % 26) + 'A');
        } else if (islower((unsigned char)c)) {
            plaintext[i] = (char)(((c - 'a' - (tolower((unsigned char)k) - 'a') + 26) % 26) + 'a');
        } else {
            plaintext[i] = c;
        }
    }
    plaintext[len] = '\0';
}

int main(void) {
    char keyword[MAX_LEN];
    char clean_key[MAX_LEN];
    char plaintext[MAX_LEN];
    char keystream[MAX_LEN];
    char ciphertext[MAX_LEN];
    char decrypted[MAX_LEN];

    printf("=================================================================\n");
    printf("   EXPERIMENT 4: POLYALPHABETIC SUBSTITUTION CIPHER (VIGENERE)   \n");
    printf("=================================================================\n\n");

    printf("Enter keyword: ");
    if (fgets(keyword, sizeof(keyword), stdin) == NULL || strlen(keyword) <= 1) {
        strcpy(keyword, "PASCAL");
        printf("%s\n", keyword);
    } else {
        keyword[strcspn(keyword, "\r\n")] = '\0';
    }

    // Filter alphabetic letters for key
    int k_count = 0;
    for (int i = 0; keyword[i] != '\0'; i++) {
        if (isalpha((unsigned char)keyword[i])) {
            clean_key[k_count++] = (char)toupper((unsigned char)keyword[i]);
        }
    }
    clean_key[k_count] = '\0';
    if (k_count == 0) {
        strcpy(clean_key, "PASCAL");
    }

    printf("Enter plaintext: ");
    if (fgets(plaintext, sizeof(plaintext), stdin) == NULL || strlen(plaintext) <= 1) {
        strcpy(plaintext, "She is listening to the radio");
        printf("%s\n", plaintext);
    } else {
        plaintext[strcspn(plaintext, "\r\n")] = '\0';
    }

    generate_keystream(plaintext, clean_key, keystream);
    vigenere_encrypt(plaintext, keystream, ciphertext);
    vigenere_decrypt(ciphertext, keystream, decrypted);

    printf("\n-----------------------------------------------------------------\n");
    printf("RESULTS & VERIFICATION:\n");
    printf("-----------------------------------------------------------------\n");
    printf("Original Plaintext  : %s\n", plaintext);
    printf("Keyword             : %s\n", clean_key);
    printf("Generated Keystream : %s\n", keystream);
    printf("Encrypted Ciphertext: %s\n", ciphertext);
    printf("Decrypted Plaintext : %s\n", decrypted);

    if (strcmp(plaintext, decrypted) == 0) {
        printf("\n[+] Verification SUCCESS: Recovered plaintext matches original.\n");
    } else {
        printf("\n[-] Verification FAILED: Decrypted text does not match.\n");
    }
    printf("=================================================================\n");

    return 0;
}
