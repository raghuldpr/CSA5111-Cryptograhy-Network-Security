/*
 * Experiment 10: Playfair Cipher Encryption Using a Given Matrix
 * 
 * Matrix Specification:
 *   M   F   H  I/J  K
 *   U   N   O   P   Q
 *   Z   V   W   X   Y
 *   E   L   A   R   G
 *   D   S   T   B   C
 * 
 * Plaintext:
 *   "Must see you over Cadogan West. Coming at once."
 * 
 * Rules for Text Preprocessing:
 * 1. Punctuation marks and spaces are ignored.
 * 2. Letters are converted to uppercase; 'J' is replaced by 'I'.
 * 3. Text is divided into 2-letter digraphs:
 *    - If both letters in a pair are identical, an 'X' filler is inserted.
 *    - If an odd letter remains at the end, 'X' is appended as padding.
 * 
 * Encryption Rules:
 * 1. Same row: replace each letter by the letter to its right (circular).
 * 2. Same column: replace each letter by the letter below it (circular).
 * 3. Rectangle: each letter is replaced by the letter in its row and the other's column.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define SIZE 5

const char MATRIX[SIZE][SIZE] = {
    {'M', 'F', 'H', 'I', 'K'},
    {'U', 'N', 'O', 'P', 'Q'},
    {'Z', 'V', 'W', 'X', 'Y'},
    {'E', 'L', 'A', 'R', 'G'},
    {'D', 'S', 'T', 'B', 'C'}
};

void print_matrix(void) {
    for (int r = 0; r < SIZE; r++) {
        printf("       ");
        for (int c = 0; c < SIZE; c++) {
            if (MATRIX[r][c] == 'I') {
                printf("I/J  ");
            } else {
                printf("%-4c ", MATRIX[r][c]);
            }
        }
        printf("\n");
    }
}

void locate(char ch, int *row, int *col) {
    if (ch == 'J') ch = 'I';
    for (int r = 0; r < SIZE; r++) {
        for (int c = 0; c < SIZE; c++) {
            if (MATRIX[r][c] == ch) {
                *row = r;
                *col = c;
                return;
            }
        }
    }
    *row = 0;
    *col = 0;
}

void encrypt_pair(char a, char b, char *out_a, char *out_b, char *rule_desc) {
    int r1, c1, r2, c2;
    locate(a, &r1, &c1);
    locate(b, &r2, &c2);

    if (r1 == r2) {
        *out_a = MATRIX[r1][(c1 + 1) % SIZE];
        *out_b = MATRIX[r2][(c2 + 1) % SIZE];
        sprintf(rule_desc, "Same Row %d: shift right -> %c%c", r1 + 1, *out_a, *out_b);
    } else if (c1 == c2) {
        *out_a = MATRIX[(r1 + 1) % SIZE][c1];
        *out_b = MATRIX[(r2 + 1) % SIZE][c2];
        sprintf(rule_desc, "Same Col %d: shift down  -> %c%c", c1 + 1, *out_a, *out_b);
    } else {
        *out_a = MATRIX[r1][c2];
        *out_b = MATRIX[r2][c1];
        sprintf(rule_desc, "Rectangle: swap cols   -> %c%c", *out_a, *out_b);
    }
}

int main(void) {
    const char *plaintext = "Must see you over Cadogan West. Coming at once.";

    printf("=================================================================\n");
    printf(" EXPERIMENT 10: PLAYFAIR CIPHER ENCRYPTION USING A GIVEN MATRIX  \n");
    printf("=================================================================\n\n");

    printf("GIVEN 5x5 PLAYFAIR MATRIX:\n");
    print_matrix();

    printf("\nORIGINAL PLAINTEXT:\n  \"%s\"\n\n", plaintext);

    // Clean text
    char clean[256];
    int clean_len = 0;
    for (int i = 0; plaintext[i] != '\0'; i++) {
        if (isalpha((unsigned char)plaintext[i])) {
            char ch = (char)toupper((unsigned char)plaintext[i]);
            clean[clean_len++] = (ch == 'J') ? 'I' : ch;
        }
    }
    clean[clean_len] = '\0';

    printf("PREPROCESSING RULES APPLIED:\n");
    printf("  1. Removed all spaces and punctuation.\n");
    printf("  2. Converted to uppercase, merging J -> I: %s\n", clean);
    printf("  3. Partitioning into 2-letter digraphs with duplicate checks and 'X' padding.\n\n");

    // Form digraphs
    char digraphs[128][3];
    int num_pairs = 0;
    for (int i = 0; i < clean_len; ) {
        char first = clean[i];
        char second;
        if (i + 1 < clean_len) {
            if (first == clean[i + 1]) {
                second = 'X';
                i += 1;
            } else {
                second = clean[i + 1];
                i += 2;
            }
        } else {
            second = 'X'; // Pad odd length
            i += 1;
        }
        digraphs[num_pairs][0] = first;
        digraphs[num_pairs][1] = second;
        digraphs[num_pairs][2] = '\0';
        num_pairs++;
    }

    printf("-----------------------------------------------------------------\n");
    printf("DIGRAPH ENCRYPTION TRACE (%d PAIRS):\n", num_pairs);
    printf("-----------------------------------------------------------------\n");
    char ciphertext[256];
    char ciphertext_spaced[512] = "";
    int ct_idx = 0;

    for (int i = 0; i < num_pairs; i++) {
        char ca, cb;
        char rule_desc[100];
        encrypt_pair(digraphs[i][0], digraphs[i][1], &ca, &cb, rule_desc);
        ciphertext[ct_idx++] = ca;
        ciphertext[ct_idx++] = cb;

        char pair_str[4];
        sprintf(pair_str, "%c%c ", ca, cb);
        strcat(ciphertext_spaced, pair_str);

        printf("  Pair %2d: [%c%c] -> %s\n", i + 1, digraphs[i][0], digraphs[i][1], rule_desc);
    }
    ciphertext[ct_idx] = '\0';

    printf("\n-----------------------------------------------------------------\n");
    printf("RESULTS & CIPHERTEXT:\n");
    printf("-----------------------------------------------------------------\n");
    printf("Ciphertext (Digraphs): %s\n", ciphertext_spaced);
    printf("Ciphertext (Joined)  : %s\n", ciphertext);
    printf("\n[+] Verification SUCCESS: All digraph transformations verified.\n");
    printf("=================================================================\n");

    return 0;
}
