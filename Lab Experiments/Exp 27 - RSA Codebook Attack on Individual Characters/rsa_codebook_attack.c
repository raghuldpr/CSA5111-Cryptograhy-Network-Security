/*
 * ============================================================================
 * Experiment 27: RSA Codebook Attack on Individual Characters
 * 
 * Objective:
 *   Demonstrate a codebook (dictionary) attack on deterministic RSA when applied
 *   to individual characters (message space of size 26: A=0, B=1, ..., Z=25).
 * 
 * Cryptographic Vulnerability:
 *   RSA encryption is deterministic: C = (M^e) mod n.
 *   When the message space is small (only 26 possible values for letters A-Z):
 *     1. The attacker knows the public key (e, n).
 *     2. The attacker precomputes a lookup table (codebook) by encrypting all
 *        26 characters: Codebook[m] = (m^e) mod n for m in 0..25.
 *     3. For any intercepted ciphertext C_i, the attacker finds C_i in the
 *        codebook and immediately recovers character m.
 *     4. The private key d and prime factors of n are NEVER needed!
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_MSG_LEN 512

// Modular exponentiation using Repeated Squaring: (base^exp) mod mod
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

// Structure to hold codebook entry
typedef struct {
    char letter;
    int numeric_val;
    long long ciphertext;
} CodebookEntry;

int main(void) {
    long long e, n;
    char message[MAX_MSG_LEN];
    long long ciphertext_blocks[MAX_MSG_LEN];
    char recovered_message[MAX_MSG_LEN];
    CodebookEntry codebook[26];

    printf("====================================================================\n");
    printf("   EXP 27: RSA CODEBOOK ATTACK ON INDIVIDUAL CHARACTERS            \n");
    printf("====================================================================\n\n");

    // 1. Inputs
    printf("Enter RSA public exponent e (e.g., 17)  : ");
    if (scanf("%lld", &e) != 1 || e <= 1) {
        printf("Error: Invalid exponent e.\n");
        return 1;
    }

    printf("Enter RSA modulus n         (e.g., 3233): ");
    if (scanf("%lld", &n) != 1 || n <= 26) {
        printf("Error: Invalid modulus n.\n");
        return 1;
    }

    printf("Enter uppercase plaintext   (e.g., HELLO): ");
    if (scanf("%511s", message) != 1) {
        printf("Error: Failed to read message.\n");
        return 1;
    }

    int msg_len = strlen(message);
    for (int i = 0; i < msg_len; i++) {
        if (!isupper((unsigned char)message[i])) {
            printf("Error: Plaintext must contain only uppercase letters (A-Z).\n");
            return 1;
        }
    }

    // 2. Generate Attacker's Codebook (Precomputation using ONLY Public Key)
    printf("\n--------------------------------------------------------------------\n");
    printf("ATTACKER'S PRECOMPUTED CODEBOOK (Only uses Public Key e=%lld, n=%lld):\n", e, n);
    printf("Formula: C = (m^e) mod n for m in {0..25}\n");
    printf("--------------------------------------------------------------------\n");
    printf(" Char | Value | Ciphertext  ||  Char | Value | Ciphertext\n");
    printf("------+-------+-------------++-------+-------+-------------\n");

    for (int m = 0; m < 26; m++) {
        codebook[m].letter = (char)('A' + m);
        codebook[m].numeric_val = m;
        codebook[m].ciphertext = mod_exp(m, e, n);
    }

    for (int m = 0; m < 13; m++) {
        int m2 = m + 13;
        printf("  %c   |  %2d   | %10lld  ||   %c   |  %2d   | %10lld\n",
               codebook[m].letter, codebook[m].numeric_val, codebook[m].ciphertext,
               codebook[m2].letter, codebook[m2].numeric_val, codebook[m2].ciphertext);
    }

    // 3. Sender Encrypts Characters Separately
    printf("\n--------------------------------------------------------------------\n");
    printf("SENDER: CHARACTER-BY-CHARACTER RSA ENCRYPTION:\n");
    printf("--------------------------------------------------------------------\n");
    printf("Original Plaintext: %s\n", message);
    printf("Character Encryptions:\n");
    for (int i = 0; i < msg_len; i++) {
        int m = message[i] - 'A';
        ciphertext_blocks[i] = mod_exp(m, e, n);
        printf("  '%c' (m = %2d) -> (%2d^%lld) mod %lld = %lld\n",
               message[i], m, m, e, n, ciphertext_blocks[i]);
    }

    printf("\n--> Transmitted Ciphertext Blocks:\n    ");
    for (int i = 0; i < msg_len; i++) {
        printf("%lld%s", ciphertext_blocks[i], (i == msg_len - 1) ? "" : " ");
    }
    printf("\n");

    // 4. Attacker Intercepts and Breaks Ciphertext using Codebook Lookup
    printf("\n--------------------------------------------------------------------\n");
    printf("ATTACKER: CODEBOOK LOOKUP ATTACK (NO PRIVATE KEY USED!):\n");
    printf("--------------------------------------------------------------------\n");
    for (int i = 0; i < msg_len; i++) {
        long long c = ciphertext_blocks[i];
        char recovered_char = '?';
        int found_val = -1;

        // Linear search in the precomputed codebook of 26 entries
        for (int m = 0; m < 26; m++) {
            if (codebook[m].ciphertext == c) {
                recovered_char = codebook[m].letter;
                found_val = codebook[m].numeric_val;
                break;
            }
        }

        recovered_message[i] = recovered_char;
        printf("  Ciphertext block %10lld -> Matched in codebook: '%c' (value %2d)\n",
               c, recovered_char, found_val);
    }
    recovered_message[msg_len] = '\0';

    printf("\n--> Attacker Recovered Plaintext: %s\n", recovered_message);

    // 5. Verification
    printf("\n====================================================================\n");
    printf("ATTACK VERIFICATION & SECURITY ANALYSIS:\n");
    printf("====================================================================\n");
    if (strcmp(message, recovered_message) == 0) {
        printf("[SUCCESS] Full plaintext \"%s\" recovered without private key!\n", recovered_message);
    } else {
        printf("[FAILED] Plaintext recovery failed.\n");
    }

    printf("\nWhy this attack works:\n");
    printf("1. Determinism: Textbook RSA always encrypts the same plaintext to the\n");
    printf("   same ciphertext under a given key.\n");
    printf("2. Small Message Space: With only 26 possible plaintexts, an eavesdropper\n");
    printf("   pre-encrypts all 26 values in negligible time (26 modular exponentiations).\n");
    printf("3. Insecurity: Factoring n or finding private key d is completely UNNECESSARY.\n");
    printf("4. Defense: Never encrypt single characters with RSA. Always use large\n");
    printf("   blocks and randomized padding schemes such as RSA-OAEP (Optimal\n");
    printf("   Asymmetric Encryption Padding).\n");
    printf("====================================================================\n");

    return 0;
}
