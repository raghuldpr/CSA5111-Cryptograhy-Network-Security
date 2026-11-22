/*
 * ============================================================================
 * Experiment 35: One-Time Pad Version of the Vigenere Cipher
 *
 * Objective:
 *   Demonstrate the One-Time Pad (OTP) variant of the Vigenere Cipher using
 *   an integer keystream where each integer in the range [0, 25] dictates
 *   the individual shift for the corresponding plaintext letter.
 *
 * Mathematical Foundations:
 *   Encryption Formula:
 *     C_i = (P_i + K_i) mod 26
 *
 *   Decryption Formula:
 *     P_i = (C_i - K_i + 26) mod 26
 *
 * One-Time Pad Properties (Vernam Cipher / Shannon Perfect Secrecy):
 *   1. Keystream length must be at least as long as the plaintext.
 *   2. Keystream values must be truly random (uniform probability distribution).
 *   3. Keystream must be used EXACTLY ONCE (never reused).
 *   4. Keystream must be kept completely secret between sender and receiver.
 *
 * Security Note:
 *   Standard C library rand() is a pseudo-random number generator (PRNG) and
 *   is NOT cryptographically secure. For a true physical OTP, hardware entropy
 *   sources (e.g., thermal noise, radioactive decay) are mandatory.
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#define MAX_TEXT_LEN 1024

// Modular addition encryption: C = (P + K) mod 26
char otp_encrypt_char(char p, int k) {
    if (isupper(p)) {
        return (char)(((p - 'A' + k) % 26) + 'A');
    } else if (islower(p)) {
        return (char)(((p - 'a' + k) % 26) + 'a');
    }
    return p; // Preserve non-alphabetic characters
}

// Modular subtraction decryption: P = (C - K + 26) mod 26
char otp_decrypt_char(char c, int k) {
    if (isupper(c)) {
        return (char)(((c - 'A' - k + 26) % 26) + 'A');
    } else if (islower(c)) {
        return (char)(((c - 'a' - k + 26) % 26) + 'a');
    }
    return c; // Preserve non-alphabetic characters
}

int main(void) {
    char plaintext[MAX_TEXT_LEN];
    char ciphertext[MAX_TEXT_LEN];
    char decrypted[MAX_TEXT_LEN];
    int keystream[MAX_TEXT_LEN];
    int alpha_count = 0;
    int choice;

    printf("====================================================================\n");
    printf("   EXPERIMENT 35: ONE-TIME PAD VERSION OF THE VIGENERE CIPHER       \n");
    printf("====================================================================\n\n");

    // 1. Accept plaintext
    printf("Enter Plaintext string:\n> ");
    if (fgets(plaintext, sizeof(plaintext), stdin) == NULL) {
        printf("[ERROR] Failed to read input.\n");
        return 1;
    }
    plaintext[strcspn(plaintext, "\r\n")] = '\0';

    // Count alphabetic characters
    int len = strlen(plaintext);
    for (int i = 0; i < len; i++) {
        if (isalpha(plaintext[i])) {
            alpha_count++;
        }
    }

    if (alpha_count == 0) {
        printf("[ERROR] Plaintext must contain at least one alphabetic character.\n");
        return 1;
    }

    printf("[*] Plaintext length: %d chars (%d alphabetic characters needing keys)\n\n",
           len, alpha_count);

    // 2. Select Keystream input mode
    printf("Keystream Generation Mode:\n");
    printf("  1. Enter keystream integers manually (values 0 - 25)\n");
    printf("  2. Generate random keystream automatically\n");
    printf("Select mode (1 or 2): ");
    if (scanf("%d", &choice) != 1) choice = 1;

    if (choice == 1) {
        printf("\nEnter %d keystream integers (0 - 25, space-separated):\n> ", alpha_count);
        for (int i = 0; i < alpha_count; i++) {
            if (scanf("%d", &keystream[i]) != 1) {
                printf("[ERROR] Failed reading keystream value at index %d.\n", i);
                return 1;
            }
            if (keystream[i] < 0 || keystream[i] > 25) {
                printf("[WARNING] Key value %d out of range [0, 25]. Applying mod 26.\n", keystream[i]);
                keystream[i] = (keystream[i] % 26 + 26) % 26;
            }
        }
    } else {
        printf("\n[*] Generating %d pseudo-random keystream shifts [0 - 25]...\n", alpha_count);
        srand((unsigned int)time(NULL));
        for (int i = 0; i < alpha_count; i++) {
            keystream[i] = rand() % 26;
        }
        printf("Keystream: ");
        for (int i = 0; i < alpha_count; i++) {
            printf("%d ", keystream[i]);
        }
        printf("\n");
        printf("[SECURITY NOTE] Standard rand() is a pseudo-random PRNG. For genuine\n");
        printf("unconditional security (Shannon secrecy), a true physical entropy source\n");
        printf("must be used, each key used only once, and never repeated.\n");
    }

    // 3. Encrypt and Decrypt character-by-character
    int k_idx = 0;
    for (int i = 0; i < len; i++) {
        if (isalpha(plaintext[i])) {
            int k = keystream[k_idx++];
            ciphertext[i] = otp_encrypt_char(plaintext[i], k);
            decrypted[i] = otp_decrypt_char(ciphertext[i], k);
        } else {
            ciphertext[i] = plaintext[i];
            decrypted[i] = plaintext[i];
        }
    }
    ciphertext[len] = '\0';
    decrypted[len] = '\0';

    // 4. Detailed Character Transformation Table
    printf("\n--------------------------------------------------------------------\n");
    printf("                 CHARACTER TRANSFORMATION BREAKDOWN                 \n");
    printf("--------------------------------------------------------------------\n");
    printf("%-5s | %-6s | %-4s | %-16s | %-6s | %-16s\n",
           "Char", "P_val", "Key", "Enc Formula", "C_val", "Dec Formula");
    printf("--------------------------------------------------------------------\n");

    k_idx = 0;
    for (int i = 0; i < len; i++) {
        if (isalpha(plaintext[i])) {
            int base = isupper(plaintext[i]) ? 'A' : 'a';
            int p_val = plaintext[i] - base;
            int k = keystream[k_idx++];
            int c_val = (p_val + k) % 26;
            printf("  %c   |  %2d    | %2d  | (%2d + %2d) %% 26 = %2d  |  %c (%2d) | (%2d - %2d) %% 26 = %2d\n",
                   plaintext[i], p_val, k, p_val, k, c_val,
                   ciphertext[i], c_val, c_val, k, p_val);
        }
    }

    // 5. Final Results
    printf("\n====================================================================\n");
    printf("                         FINAL RESULTS                              \n");
    printf("====================================================================\n");
    printf("Original Plaintext  : %s\n", plaintext);
    printf("Applied Keystream   : ");
    for (int i = 0; i < alpha_count; i++) {
        printf("%d ", keystream[i]);
    }
    printf("\n");
    printf("Encrypted Ciphertext: %s\n", ciphertext);
    printf("Decrypted Plaintext : %s\n", decrypted);
    printf("====================================================================\n");

    if (strcmp(plaintext, decrypted) == 0) {
        printf("[SUCCESS] Decrypted text matches original plaintext perfectly!\n");
    } else {
        printf("[ERROR] Decrypted text mismatch!\n");
    }

    return 0;
}
