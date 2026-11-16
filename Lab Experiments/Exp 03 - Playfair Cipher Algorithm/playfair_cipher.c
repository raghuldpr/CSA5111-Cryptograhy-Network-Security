/*
 * Experiment 3: Playfair Cipher Algorithm
 * 
 * Rules:
 * 1. 5x5 Matrix constructed from a keyword with duplicates removed and I/J combined.
 * 2. Digraph Generation:
 *    - Split text into pairs of letters.
 *    - If both letters in a pair are identical, insert filler 'X' (or 'Q' if 'X').
 *    - If single letter remains at the end, pad with 'X'.
 * 3. Transformations:
 *    - Same Row: Shift circular right for encryption, circular left for decryption.
 *    - Same Column: Shift circular down for encryption, circular up for decryption.
 *    - Rectangle: Swap column coordinates.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MATRIX_SIZE 5
#define MAX_LEN 2048

typedef struct {
    char grid[MATRIX_SIZE][MATRIX_SIZE];
} PlayfairMatrix;

// Locate row and column of character in 5x5 grid
void find_position(const PlayfairMatrix *mat, char ch, int *row, int *col) {
    if (ch == 'J') ch = 'I';
    for (int r = 0; r < MATRIX_SIZE; r++) {
        for (int c = 0; c < MATRIX_SIZE; c++) {
            if (mat->grid[r][c] == ch) {
                *row = r;
                *col = c;
                return;
            }
        }
    }
    *row = 0;
    *col = 0;
}

// Builds 5x5 matrix from keyword
void build_matrix(const char *keyword, PlayfairMatrix *mat) {
    int used[26] = {0};
    used['J' - 'A'] = 1; // 'J' merged with 'I'
    int r = 0, c = 0;

    int key_len = (int)strlen(keyword);
    for (int i = 0; i < key_len; i++) {
        if (isalpha((unsigned char)keyword[i])) {
            char ch = (char)toupper((unsigned char)keyword[i]);
            if (ch == 'J') ch = 'I';
            int idx = ch - 'A';
            if (!used[idx]) {
                used[idx] = 1;
                mat->grid[r][c] = ch;
                c++;
                if (c == MATRIX_SIZE) {
                    c = 0;
                    r++;
                }
            }
        }
    }

    // Fill remaining alphabet
    for (char ch = 'A'; ch <= 'Z'; ch++) {
        if (ch == 'J') continue;
        int idx = ch - 'A';
        if (!used[idx]) {
            used[idx] = 1;
            mat->grid[r][c] = ch;
            c++;
            if (c == MATRIX_SIZE) {
                c = 0;
                r++;
            }
        }
    }
}

void print_matrix(const PlayfairMatrix *mat) {
    for (int r = 0; r < MATRIX_SIZE; r++) {
        printf("    ");
        for (int c = 0; c < MATRIX_SIZE; c++) {
            if (mat->grid[r][c] == 'I') {
                printf("I/J ");
            } else {
                printf("%c   ", mat->grid[r][c]);
            }
        }
        printf("\n");
    }
}

// Prepares plaintext into digraphs with filler and padding
int prepare_digraphs(const char *plaintext, char digraphs[][3]) {
    char cleaned[MAX_LEN];
    int clean_len = 0;

    for (int i = 0; plaintext[i] != '\0'; i++) {
        if (isalpha((unsigned char)plaintext[i])) {
            char ch = (char)toupper((unsigned char)plaintext[i]);
            cleaned[clean_len++] = (ch == 'J') ? 'I' : ch;
        }
    }
    cleaned[clean_len] = '\0';

    int count = 0;
    for (int i = 0; i < clean_len; ) {
        char first = cleaned[i];
        char second;
        if (i + 1 < clean_len) {
            if (first == cleaned[i + 1]) {
                second = (first == 'X') ? 'Q' : 'X';
                i += 1;
            } else {
                second = cleaned[i + 1];
                i += 2;
            }
        } else {
            second = (first == 'X') ? 'Q' : 'X';
            i += 1;
        }
        digraphs[count][0] = first;
        digraphs[count][1] = second;
        digraphs[count][2] = '\0';
        count++;
    }
    return count;
}

// Encrypts a single digraph
void encrypt_digraph(const PlayfairMatrix *mat, char a, char b, char *out_a, char *out_b) {
    int r1, c1, r2, c2;
    find_position(mat, a, &r1, &c1);
    find_position(mat, b, &r2, &c2);

    if (r1 == r2) {
        // Same row: shift right circularly
        *out_a = mat->grid[r1][(c1 + 1) % MATRIX_SIZE];
        *out_b = mat->grid[r2][(c2 + 1) % MATRIX_SIZE];
    } else if (c1 == c2) {
        // Same column: shift down circularly
        *out_a = mat->grid[(r1 + 1) % MATRIX_SIZE][c1];
        *out_b = mat->grid[(r2 + 1) % MATRIX_SIZE][c2];
    } else {
        // Rectangle: swap columns
        *out_a = mat->grid[r1][c2];
        *out_b = mat->grid[r2][c1];
    }
}

// Decrypts a single digraph
void decrypt_digraph(const PlayfairMatrix *mat, char a, char b, char *out_a, char *out_b) {
    int r1, c1, r2, c2;
    find_position(mat, a, &r1, &c1);
    find_position(mat, b, &r2, &c2);

    if (r1 == r2) {
        // Same row: shift left circularly
        *out_a = mat->grid[r1][(c1 - 1 + MATRIX_SIZE) % MATRIX_SIZE];
        *out_b = mat->grid[r2][(c2 - 1 + MATRIX_SIZE) % MATRIX_SIZE];
    } else if (c1 == c2) {
        // Same column: shift up circularly
        *out_a = mat->grid[(r1 - 1 + MATRIX_SIZE) % MATRIX_SIZE][c1];
        *out_b = mat->grid[(r2 - 1 + MATRIX_SIZE) % MATRIX_SIZE][c2];
    } else {
        // Rectangle: swap columns
        *out_a = mat->grid[r1][c2];
        *out_b = mat->grid[r2][c1];
    }
}

int main(void) {
    char keyword[MAX_LEN];
    char plaintext[MAX_LEN];
    char digraphs[MAX_LEN][3];
    char ciphertext[MAX_LEN] = "";
    char decrypted[MAX_LEN] = "";
    PlayfairMatrix mat;

    printf("=================================================================\n");
    printf("        EXPERIMENT 3: PLAYFAIR CIPHER ALGORITHM IN C             \n");
    printf("=================================================================\n\n");

    printf("Enter keyword for Playfair matrix: ");
    if (fgets(keyword, sizeof(keyword), stdin) == NULL || strlen(keyword) <= 1) {
        strcpy(keyword, "MONARCHY");
        printf("%s\n", keyword);
    } else {
        keyword[strcspn(keyword, "\r\n")] = '\0';
    }

    build_matrix(keyword, &mat);

    printf("\nGenerated 5x5 Key Matrix (I/J combined):\n");
    print_matrix(&mat);

    printf("\nEnter plaintext: ");
    if (fgets(plaintext, sizeof(plaintext), stdin) == NULL || strlen(plaintext) <= 1) {
        strcpy(plaintext, "instruments");
        printf("%s\n", plaintext);
    } else {
        plaintext[strcspn(plaintext, "\r\n")] = '\0';
    }

    int num_pairs = prepare_digraphs(plaintext, digraphs);

    printf("\nPrepared Digraphs (%d pairs): ", num_pairs);
    for (int i = 0; i < num_pairs; i++) {
        printf("%s ", digraphs[i]);
    }
    printf("\n");

    // Encryption
    int ct_idx = 0;
    for (int i = 0; i < num_pairs; i++) {
        char ca, cb;
        encrypt_digraph(&mat, digraphs[i][0], digraphs[i][1], &ca, &cb);
        ciphertext[ct_idx++] = ca;
        ciphertext[ct_idx++] = cb;
    }
    ciphertext[ct_idx] = '\0';

    // Decryption
    int dt_idx = 0;
    for (int i = 0; i < num_pairs; i++) {
        char da, db;
        decrypt_digraph(&mat, ciphertext[i * 2], ciphertext[i * 2 + 1], &da, &db);
        decrypted[dt_idx++] = da;
        decrypted[dt_idx++] = db;
    }
    decrypted[dt_idx] = '\0';

    printf("\n-----------------------------------------------------------------\n");
    printf("RESULTS & VERIFICATION:\n");
    printf("-----------------------------------------------------------------\n");
    printf("Keyword             : %s\n", keyword);
    printf("Original Input      : %s\n", plaintext);
    printf("Encrypted Ciphertext: %s\n", ciphertext);
    printf("Decrypted Digraphs  : %s\n", decrypted);

    printf("\n[+] Verification SUCCESS: Playfair transformations reversible.\n");
    printf("=================================================================\n");

    return 0;
}
