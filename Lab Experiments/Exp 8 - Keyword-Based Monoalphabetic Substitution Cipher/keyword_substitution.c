/*
 * Experiment 8: Keyword-Based Monoalphabetic Substitution Cipher
 * 
 * Algorithm:
 * 1. The user supplies a keyword (e.g., "CIPHER").
 * 2. Remove any duplicate letters from the keyword, preserving their first occurrence:
 *    "CIPHER" -> C, I, P, H, E, R
 * 3. Append the remaining unused letters of the 26-letter alphabet in alphabetical order:
 *    Alphabet : A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
 *    CipherKey: C I P H E R A B D F G J K L M N O Q S T U V W X Y Z
 * 4. Encrypt: C_i = CipherKey[P_i - 'A']
 * 5. Decrypt: P_i = PlainAlphabet[Position of C_i in CipherKey]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define ALPHABET_LEN 26
#define MAX_LEN 1024

// Generates substitution alphabet from keyword
void generate_keyword_alphabet(const char *keyword, char *cipher_alphabet) {
    int used[ALPHABET_LEN] = {0};
    int count = 0;

    // 1. Process keyword, remove duplicate letters, preserving first occurrence
    for (int i = 0; keyword[i] != '\0'; i++) {
        if (isalpha((unsigned char)keyword[i])) {
            char upper = (char)toupper((unsigned char)keyword[i]);
            int idx = upper - 'A';
            if (!used[idx]) {
                used[idx] = 1;
                cipher_alphabet[count++] = upper;
            }
        }
    }

    // 2. Append remaining unused letters of the alphabet in order
    for (char ch = 'A'; ch <= 'Z'; ch++) {
        int idx = ch - 'A';
        if (!used[idx]) {
            used[idx] = 1;
            cipher_alphabet[count++] = ch;
        }
    }
    cipher_alphabet[count] = '\0';
}

// Encrypt plaintext using generated keyword cipher alphabet
void keyword_encrypt(const char *plaintext, const char *cipher_alphabet, char *ciphertext) {
    int len = (int)strlen(plaintext);
    for (int i = 0; i < len; i++) {
        char ch = plaintext[i];
        if (isupper((unsigned char)ch)) {
            ciphertext[i] = cipher_alphabet[ch - 'A'];
        } else if (islower((unsigned char)ch)) {
            ciphertext[i] = (char)tolower((unsigned char)cipher_alphabet[ch - 'a']);
        } else {
            ciphertext[i] = ch;
        }
    }
    ciphertext[len] = '\0';
}

// Decrypt ciphertext using generated keyword cipher alphabet
void keyword_decrypt(const char *ciphertext, const char *cipher_alphabet, char *plaintext) {
    int len = (int)strlen(ciphertext);

    // Build reverse lookup table
    char reverse_map[ALPHABET_LEN];
    for (int i = 0; i < ALPHABET_LEN; i++) {
        int cipher_idx = cipher_alphabet[i] - 'A';
        reverse_map[cipher_idx] = (char)('A' + i);
    }

    for (int i = 0; i < len; i++) {
        char ch = ciphertext[i];
        if (isupper((unsigned char)ch)) {
            plaintext[i] = reverse_map[ch - 'A'];
        } else if (islower((unsigned char)ch)) {
            plaintext[i] = (char)tolower((unsigned char)reverse_map[ch - 'a']);
        } else {
            plaintext[i] = ch;
        }
    }
    plaintext[len] = '\0';
}

int main(void) {
    char keyword[MAX_LEN];
    char cipher_alphabet[ALPHABET_LEN + 1];
    char plaintext[MAX_LEN];
    char ciphertext[MAX_LEN];
    char decrypted[MAX_LEN];

    printf("=================================================================\n");
    printf(" EXPERIMENT 8: KEYWORD-BASED MONOALPHABETIC SUBSTITUTION CIPHER  \n");
    printf("=================================================================\n\n");

    printf("Enter keyword (e.g., SECRET): ");
    if (fgets(keyword, sizeof(keyword), stdin) == NULL || strlen(keyword) <= 1) {
        strcpy(keyword, "CRYPTOGRAPHY");
        printf("%s\n", keyword);
    } else {
        keyword[strcspn(keyword, "\r\n")] = '\0';
    }

    generate_keyword_alphabet(keyword, cipher_alphabet);

    printf("\nEnter plaintext: ");
    if (fgets(plaintext, sizeof(plaintext), stdin) == NULL || strlen(plaintext) <= 1) {
        strcpy(plaintext, "Information Security Lab");
        printf("%s\n", plaintext);
    } else {
        plaintext[strcspn(plaintext, "\r\n")] = '\0';
    }

    keyword_encrypt(plaintext, cipher_alphabet, ciphertext);
    keyword_decrypt(ciphertext, cipher_alphabet, decrypted);

    printf("\n-----------------------------------------------------------------\n");
    printf("GENERATED SUBSTITUTION ALPHABET:\n");
    printf("-----------------------------------------------------------------\n");
    printf("Plain Alphabet : ABCDEFGHIJKLMNOPQRSTUVWXYZ\n");
    printf("Cipher Alphabet: %s\n", cipher_alphabet);

    printf("\n-----------------------------------------------------------------\n");
    printf("RESULTS & VERIFICATION:\n");
    printf("-----------------------------------------------------------------\n");
    printf("Keyword Applied     : %s\n", keyword);
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
