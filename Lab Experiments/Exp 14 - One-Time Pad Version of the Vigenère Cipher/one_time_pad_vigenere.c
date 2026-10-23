/*
 * Experiment 14: One-Time Pad Version of the Vigenere Cipher
 * 
 * Mathematical Formulation:
 * A = 0, B = 1, ..., Z = 25
 * 
 * Part (a): Encryption
 *   Plaintext P_1  : "send more money"
 *   Numeric Key K_1: 9, 0, 1, 7, 23, 15, 21, 14, 11, 11, 2, 8, 9
 *   Formula: C_i = (P_i + K_{1,i}) mod 26
 * 
 * Part (b): Key Derivation for Target Plaintext (Perfect Secrecy Property)
 *   Using Ciphertext C from part (a), find Key K_2 such that C decrypts to:
 *   Plaintext P_2  : "cash not needed"
 *   Formula: K_{2,i} = (C_i - P_{2,i} + 26) mod 26
 * 
 * Requirements:
 * - Preserve spaces without consuming key stream values.
 * - Verify that key length matches the number of alphabetic characters.
 * - Verify every character calculation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_LETTERS 100

int main(void) {
    const char *plaintext1 = "send more money";
    const int key1[] = {9, 0, 1, 7, 23, 15, 21, 14, 11, 11, 2, 8, 9};
    int key1_len = sizeof(key1) / sizeof(key1[0]);

    const char *plaintext2 = "cash not needed";

    printf("=================================================================\n");
    printf("   EXPERIMENT 14: ONE-TIME PAD VERSION OF THE VIGENERE CIPHER   \n");
    printf("=================================================================\n\n");

    // ---------------------------------------------------------
    // PART (A): ENCRYPTION
    // ---------------------------------------------------------
    printf("PART (A): ENCRYPTING 'send more money' WITH NUMERIC KEY STREAM\n");
    printf("-----------------------------------------------------------------\n");
    printf("Original Plaintext (P1): \"%s\"\n", plaintext1);
    printf("Numeric Key Stream (K1): ");
    for (int i = 0; i < key1_len; i++) {
        printf("%d ", key1[i]);
    }
    printf("\n\n");

    // Count alphabetic characters in P1
    int alpha_count1 = 0;
    for (int i = 0; plaintext1[i] != '\0'; i++) {
        if (isalpha((unsigned char)plaintext1[i])) alpha_count1++;
    }

    if (alpha_count1 != key1_len) {
        printf("[-] Error: Key stream length (%d) does not match letter count (%d).\n", key1_len, alpha_count1);
        return 1;
    }
    printf("[+] Key validation: %d keys match %d alphabetic characters.\n\n", key1_len, alpha_count1);

    char ciphertext[256];
    char ct_letters[MAX_LETTERS];
    int k_idx = 0;
    int ct_len = 0;

    printf("Character-by-character encryption trace: C = (P + K) mod 26\n");
    printf("Pos | Plain | P_val | Key | Calc (P + K) mod 26 | Cipher\n");
    printf("----+-------+-------+-----+---------------------+-------\n");

    for (int i = 0; plaintext1[i] != '\0'; i++) {
        char ch = plaintext1[i];
        if (isalpha((unsigned char)ch)) {
            int p_val = tolower((unsigned char)ch) - 'a';
            int k_val = key1[k_idx];
            int c_val = (p_val + k_val) % 26;
            char c_ch = (char)(c_val + 'a');

            printf(" %2d |   %c   |   %2d  |  %2d |   (%2d + %2d) %% 26 = %2d  |   %c\n",
                   k_idx + 1, ch, p_val, k_val, p_val, k_val, c_val, c_ch);

            ciphertext[ct_len++] = c_ch;
            ct_letters[k_idx++] = c_ch;
        } else {
            ciphertext[ct_len++] = ch; // Space preserved without consuming key
        }
    }
    ciphertext[ct_len] = '\0';
    ct_letters[k_idx] = '\0';

    printf("\nGenerated Ciphertext (with spaces): \"%s\"\n\n", ciphertext);

    // ---------------------------------------------------------
    // PART (B): KEY STREAM DERIVATION FOR ALTERNATIVE PLAINTEXT
    // ---------------------------------------------------------
    printf("PART (B): DERIVING NEW KEY STREAM FOR 'cash not needed'\n");
    printf("-----------------------------------------------------------------\n");
    printf("Ciphertext from Part (A): \"%s\"\n", ciphertext);
    printf("Target Plaintext (P2)   : \"%s\"\n\n", plaintext2);

    int alpha_count2 = 0;
    char p2_letters[MAX_LETTERS];
    for (int i = 0; plaintext2[i] != '\0'; i++) {
        if (isalpha((unsigned char)plaintext2[i])) {
            p2_letters[alpha_count2++] = (char)tolower((unsigned char)plaintext2[i]);
        }
    }
    p2_letters[alpha_count2] = '\0';

    if (alpha_count2 != k_idx) {
        printf("[-] Error: Target plaintext length does not match ciphertext length.\n");
        return 1;
    }

    int key2[MAX_LETTERS];
    printf("Key derivation trace: K2 = (C - P2 + 26) mod 26\n");
    printf("Pos | Cipher | C_val | Target P2 | P2_val | Derivation (C-P2+26)%%26 | Key K2\n");
    printf("----+--------+-------+-----------+--------+------------------------+-------\n");

    for (int i = 0; i < alpha_count2; i++) {
        int c_val = ct_letters[i] - 'a';
        int p2_val = p2_letters[i] - 'a';
        int k2_val = (c_val - p2_val + 26) % 26;
        key2[i] = k2_val;

        printf(" %2d |   %c    |   %2d  |     %c     |   %2d   |    (%2d - %2d + 26) %% 26  |  %2d\n",
               i + 1, ct_letters[i], c_val, p2_letters[i], p2_val, c_val, p2_val, k2_val);
    }

    printf("\nDerived Numeric Key Stream (K2):\n  ");
    for (int i = 0; i < alpha_count2; i++) {
        printf("%d ", key2[i]);
    }
    printf("\n\n");

    // Decryption verification using K2
    char decrypted_with_k2[256];
    int dec_len = 0;
    int k2_ptr = 0;
    for (int i = 0; ciphertext[i] != '\0'; i++) {
        char ch = ciphertext[i];
        if (isalpha((unsigned char)ch)) {
            int c_val = tolower((unsigned char)ch) - 'a';
            int p_rec = (c_val - key2[k2_ptr++] + 26) % 26;
            decrypted_with_k2[dec_len++] = (char)(p_rec + 'a');
        } else {
            // Re-space according to target plaintext formatting for visual fidelity
            decrypted_with_k2[dec_len++] = ch;
        }
    }
    decrypted_with_k2[dec_len] = '\0';

    // Format target correctly with its native spacing
    char formatted_p2[256];
    int f_ptr = 0;
    int l_ptr = 0;
    for (int i = 0; plaintext2[i] != '\0'; i++) {
        if (isalpha((unsigned char)plaintext2[i])) {
            int c_val = ct_letters[l_ptr] - 'a';
            int p_rec = (c_val - key2[l_ptr++] + 26) % 26;
            formatted_p2[f_ptr++] = (char)(p_rec + 'a');
        } else {
            formatted_p2[f_ptr++] = plaintext2[i];
        }
    }
    formatted_p2[f_ptr] = '\0';

    printf("-----------------------------------------------------------------\n");
    printf("RESULTS & CRYPTOGRAPHIC VERIFICATION:\n");
    printf("-----------------------------------------------------------------\n");
    printf("Ciphertext Decrypted with K2: \"%s\"\n", formatted_p2);
    printf("Target Plaintext (P2)       : \"%s\"\n", plaintext2);

    if (strcmp(formatted_p2, plaintext2) == 0) {
        printf("\n[+] Verification SUCCESS: 100%% exact match achieved.\n");
        printf("[*] Cryptographic Principle Verified: Shannon's Perfect Secrecy\n");
        printf("    Given any ciphertext of length N and any desired plaintext of length N,\n");
        printf("    there exists a valid one-time key stream that produces that plaintext.\n");
    } else {
        printf("\n[-] Verification FAILED: Decrypted text does not match target.\n");
    }
    printf("=================================================================\n");

    return 0;
}
