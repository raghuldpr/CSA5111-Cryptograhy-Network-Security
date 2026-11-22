/*
 * ============================================================================
 * Experiment 39: Additive Cipher Letter Frequency Attack
 *
 * Objective:
 *   Implement an automated cryptanalytic letter frequency attack against an
 *   additive cipher (Caesar cipher). Try all 26 possible key shifts, evaluate
 *   the statistical English frequency score of each candidate plaintext,
 *   and rank candidates in descending order of likelihood.
 *
 * Mathematical Foundations:
 *   Encryption Formula:
 *     C = (P + key) mod 26
 *
 *   Decryption Formula:
 *     P = (C - key + 26) mod 26
 *
 * Cryptanalytic Feasibility:
 *   - Key Space: Exactly 26 possible keys (k in [0, 25]).
 *   - Because the key space is tiny (|K| = 26), an exhaustive key search
 *     (brute-force decryption) combined with English letter-frequency scoring
 *     is computationally trivial and 100% automated.
 *
 * Scoring Function:
 *   For each candidate decryption, every decrypted letter's frequency is
 *   weighted against the standard English single-letter frequency distribution
 *   (e.g., E = 12.02%, T = 9.10%, A = 8.12%...). The candidate achieving
 *   the highest aggregate score represents the most probable original plaintext.
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define ALPHABET_SIZE 26
#define MAX_TEXT_LEN 2048

// Standard English letter frequency distribution (percentage)
static const double ENGLISH_LETTER_FREQ[26] = {
    8.12,  /* A */
    1.49,  /* B */
    2.71,  /* C */
    4.32,  /* D */
    12.02, /* E */
    2.30,  /* F */
    2.03,  /* G */
    5.92,  /* H */
    7.31,  /* I */
    0.10,  /* J */
    0.69,  /* K */
    3.98,  /* L */
    2.61,  /* M */
    6.95,  /* N */
    7.68,  /* O */
    1.82,  /* P */
    0.11,  /* Q */
    6.02,  /* R */
    6.28,  /* S */
    9.10,  /* T */
    2.88,  /* U */
    1.11,  /* V */
    2.09,  /* W */
    0.17,  /* X */
    2.11,  /* Y */
    0.07   /* Z */
};

typedef struct {
    int key;
    double score;
    char plaintext[MAX_TEXT_LEN];
} AdditiveCandidate;

// Decrypts text under a single shift key: P = (C - key + 26) mod 26
void decrypt_additive(const char *cipher, int key, char *plain) {
    int len = strlen(cipher);
    for (int i = 0; i < len; i++) {
        char c = cipher[i];
        if (isupper(c)) {
            plain[i] = (char)(((c - 'A' - key + 26) % 26) + 'A');
        } else if (islower(c)) {
            plain[i] = (char)(((c - 'a' - key + 26) % 26) + 'a');
        } else {
            plain[i] = c;
        }
    }
    plain[len] = '\0';
}

// Computes frequency score by correlating decrypted letters with standard English
double score_additive_candidate(const char *text) {
    double score = 0.0;
    int len = strlen(text);
    for (int i = 0; i < len; i++) {
        if (isalpha(text[i])) {
            int idx = toupper(text[i]) - 'A';
            score += ENGLISH_LETTER_FREQ[idx];
        }
    }
    return score;
}

// Comparator for qsort in descending order of score
int compare_additive_candidates(const void *a, const void *b) {
    const AdditiveCandidate *ca = (const AdditiveCandidate *)a;
    const AdditiveCandidate *cb = (const AdditiveCandidate *)b;
    if (cb->score > ca->score) return 1;
    if (cb->score < ca->score) return -1;
    return 0;
}

int main(void) {
    char ciphertext[MAX_TEXT_LEN];
    AdditiveCandidate candidates[ALPHABET_SIZE];
    int top_n;

    printf("====================================================================\n");
    printf("        EXPERIMENT 39: ADDITIVE CIPHER FREQUENCY ATTACK             \n");
    printf("         (Exhaustive 26-Key Search with Frequency Scoring)          \n");
    printf("====================================================================\n\n");

    // 1. Accept ciphertext
    printf("Enter ciphertext (or press ENTER to use default test vector):\n> ");
    if (fgets(ciphertext, sizeof(ciphertext), stdin) == NULL || ciphertext[0] == '\n' || ciphertext[0] == '\r') {
        // Default ciphertext encrypted with shift key = 7
        // Plaintext: "CRYPTOGRAPHY AND NETWORK SECURITY LAB EXPERIMENT"
        strcpy(ciphertext, "JYFWAVNYHWOF HUK ULADVYR ZLJBYPAF SHI LEWLYPTLUA");
        printf("[Using Default Ciphertext]:\n%s\n\n", ciphertext);
    } else {
        ciphertext[strcspn(ciphertext, "\r\n")] = '\0';
    }

    // 2. Accept number of candidates to display
    printf("Enter number of top probable candidates to display (1 - 26, default 5): ");
    if (scanf("%d", &top_n) != 1 || top_n <= 0) {
        top_n = 5;
    }
    if (top_n > 26) top_n = 26;

    // 3. Exhaustively test all 26 possible shift keys
    for (int k = 0; k < 26; k++) {
        candidates[k].key = k;
        decrypt_additive(ciphertext, k, candidates[k].plaintext);
        candidates[k].score = score_additive_candidate(candidates[k].plaintext);
    }

    // 4. Sort candidates by score descending
    qsort(candidates, 26, sizeof(AdditiveCandidate), compare_additive_candidates);

    // 5. Display ranked top N candidates
    printf("\n====================================================================\n");
    printf("         TOP %d PROBABLE CANDIDATES (Ranked by Frequency Score)     \n", top_n);
    printf("====================================================================\n");
    printf("%-5s | %-8s | %-12s | %s\n", "Rank", "Key (k)", "Score", "Candidate Plaintext");
    printf("------+----------+--------------+-----------------------------------\n");

    for (int i = 0; i < top_n; i++) {
        printf("  #%-2d | Shift %2d |   %8.2f   | %s\n",
               i + 1, candidates[i].key, candidates[i].score, candidates[i].plaintext);
    }

    // 6. Security Analysis and Conclusion
    printf("\n====================================================================\n");
    printf("                      CRYPTANALYTIC SUMMARY                         \n");
    printf("====================================================================\n");
    printf("Best Identified Key   : Shift %d (Score: %.2f)\n",
           candidates[0].key, candidates[0].score);
    printf("Recovered Plaintext   : %s\n", candidates[0].plaintext);
    printf("\nKey Space Analysis:\n");
    printf("  - Total keyspace: |K| = 26.\n");
    printf("  - Because 26 is exceedingly small, testing all 26 shifts requires\n");
    printf("    less than 1 millisecond of computation time.\n");
    printf("  - The highest scoring candidate reliably identifies the original message\n");
    printf("    without requiring any user knowledge of the secret key.\n");
    printf("====================================================================\n");
    printf("[SUCCESS] Additive cipher frequency attack completed successfully.\n");

    return 0;
}
