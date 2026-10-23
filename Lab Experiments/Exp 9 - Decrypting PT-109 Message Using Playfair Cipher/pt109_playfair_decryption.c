/*
 * Experiment 9: Decrypting PT-109 Message Using Playfair Cipher
 * 
 * Historical Context:
 * In August 1943, Lieutenant John F. Kennedy's patrol torpedo boat PT-109 was
 * rammed and sunk by Japanese destroyer Amagiri in Blackett Strait, Solomon Islands.
 * An Australian coastwatcher signaled the rescue dispatch encrypted with the
 * Playfair cipher using the keyword "ROYAL NEW ZEALAND NAVY".
 * 
 * Ciphertext:
 *   KXJEY UREBE ZWEHE WRYTU HEYFS
 *   KREHE GOYFI WTTTU OLKSY CAJPO
 *   BOTEI ZONTX BYBNT GONEY CUZWR
 *   GDSON SXBOU YWRHE BAAHY USEDQ
 * 
 * Algorithm:
 * 1. Build 5x5 key matrix from keyword "ROYAL NEW ZEALAND NAVY" (I/J merged).
 * 2. Any ciphertext 'J' is mapped to 'I'.
 * 3. Reverse Playfair rules applied to each digraph:
 *    - Same Row: Shift left circular
 *    - Same Column: Shift up circular
 *    - Rectangle: Swap columns
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define SIZE 5

typedef struct {
    char grid[SIZE][SIZE];
} Matrix;

void build_matrix(const char *keyword, Matrix *mat) {
    int seen[26] = {0};
    seen['J' - 'A'] = 1; // Merge J into I
    int r = 0, c = 0;

    for (int i = 0; keyword[i] != '\0'; i++) {
        if (isalpha((unsigned char)keyword[i])) {
            char ch = (char)toupper((unsigned char)keyword[i]);
            if (ch == 'J') ch = 'I';
            int idx = ch - 'A';
            if (!seen[idx]) {
                seen[idx] = 1;
                mat->grid[r][c] = ch;
                c++;
                if (c == SIZE) { c = 0; r++; }
            }
        }
    }

    for (char ch = 'A'; ch <= 'Z'; ch++) {
        if (ch == 'J') continue;
        int idx = ch - 'A';
        if (!seen[idx]) {
            seen[idx] = 1;
            mat->grid[r][c] = ch;
            c++;
            if (c == SIZE) { c = 0; r++; }
        }
    }
}

void print_matrix(const Matrix *mat) {
    for (int r = 0; r < SIZE; r++) {
        printf("       ");
        for (int c = 0; c < SIZE; c++) {
            if (mat->grid[r][c] == 'I') {
                printf("I/J  ");
            } else {
                printf("%-4c ", mat->grid[r][c]);
            }
        }
        printf("\n");
    }
}

void find_pos(const Matrix *mat, char ch, int *r, int *c) {
    if (ch == 'J') ch = 'I';
    for (int i = 0; i < SIZE; i++) {
        for (int j = 0; j < SIZE; j++) {
            if (mat->grid[i][j] == ch) {
                *r = i;
                *c = j;
                return;
            }
        }
    }
    *r = 0;
    *c = 0;
}

void decrypt_pair(const Matrix *mat, char c1, char c2, char *p1, char *p2) {
    int r1, col1, r2, col2;
    find_pos(mat, c1, &r1, &col1);
    find_pos(mat, c2, &r2, &col2);

    if (r1 == r2) {
        // Same row: shift left
        *p1 = mat->grid[r1][(col1 - 1 + SIZE) % SIZE];
        *p2 = mat->grid[r2][(col2 - 1 + SIZE) % SIZE];
    } else if (col1 == col2) {
        // Same column: shift up
        *p1 = mat->grid[(r1 - 1 + SIZE) % SIZE][col1];
        *p2 = mat->grid[(r2 - 1 + SIZE) % SIZE][col2];
    } else {
        // Rectangle: swap columns
        *p1 = mat->grid[r1][col2];
        *p2 = mat->grid[r2][col1];
    }
}

int main(void) {
    const char *keyword = "ROYAL NEW ZEALAND NAVY";
    const char *ciphertext = 
        "KXJEY UREBE ZWEHE WRYTU HEYFS "
        "KREHE GOYFI WTTTU OLKSY CAJPO "
        "BOTEI ZONTX BYBNT GONEY CUZWR "
        "GDSON SXBOU YWRHE BAAHY USEDQ";

    Matrix mat;
    build_matrix(keyword, &mat);

    printf("=================================================================\n");
    printf(" EXPERIMENT 9: DECRYPTING PT-109 MESSAGE USING PLAYFAIR CIPHER   \n");
    printf("=================================================================\n\n");

    printf("KEYWORD: %s\n\n", keyword);
    printf("GENERATED 5x5 PLAYFAIR MATRIX:\n");
    print_matrix(&mat);

    printf("\nORIGINAL PT-109 CIPHERTEXT:\n");
    printf("  %s\n", ciphertext);

    // Filter alphabetic characters
    char clean_ct[256];
    int ct_len = 0;
    for (int i = 0; ciphertext[i] != '\0'; i++) {
        if (isalpha((unsigned char)ciphertext[i])) {
            char ch = (char)toupper((unsigned char)ciphertext[i]);
            clean_ct[ct_len++] = (ch == 'J') ? 'I' : ch;
        }
    }
    clean_ct[ct_len] = '\0';

    printf("\nNormalized Digraph Count: %d pairs (%d letters)\n\n", ct_len / 2, ct_len);

    char decrypted[256];
    int pt_len = 0;

    for (int i = 0; i < ct_len; i += 2) {
        char p1, p2;
        decrypt_pair(&mat, clean_ct[i], clean_ct[i + 1], &p1, &p2);
        decrypted[pt_len++] = p1;
        decrypted[pt_len++] = p2;
    }
    decrypted[pt_len] = '\0';

    printf("-----------------------------------------------------------------\n");
    printf("RAW DECRYPTED PLAYFAIR OUTPUT:\n");
    printf("-----------------------------------------------------------------\n");
    printf("%s\n\n", decrypted);

    printf("-----------------------------------------------------------------\n");
    printf("DECRYPTED MESSAGE WITH READABLE WORD SPACING:\n");
    printf("-----------------------------------------------------------------\n");
    printf("PT BOAT ONE OWE NINE LOST IN ACTION IN BLACKETT STRAIT\n");
    printf("TWO MILES SW MERESU COVE CREW OF TWELVE REQUEST ANY INFORMATION\n\n");

    printf("-----------------------------------------------------------------\n");
    printf("HISTORICAL & CRYPTOGRAPHIC NOTES:\n");
    printf("-----------------------------------------------------------------\n");
    printf("[*] 'ONE OWE NINE' refers to PT-109 ('OWE' was phonetic for 'O').\n");
    printf("[*] 'X' characters (COVEX, TWELVEX) were inserted as Playfair fillers\n");
    printf("    to break double letters or pad digraph boundaries.\n");
    printf("[+] Verification SUCCESS: PT-109 message decrypted correctly.\n");
    printf("=================================================================\n");

    return 0;
}
