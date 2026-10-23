/*
 * Experiment 12: Hill Cipher Encryption and Decryption
 * 
 * Mathematical Formulation (2x2 Hill Cipher):
 * Key Matrix K:
 *   [ k11  k12 ]   = [ 9  4 ]
 *   [ k21  k22 ]     [ 5  7 ]
 * 
 * Modulo: 26 (A=0, B=1, ..., Z=25)
 * 
 * Determinant:
 *   det(K) = (k11 * k22 - k12 * k21) mod 26
 *   det(K) = (9 * 7 - 4 * 5) = 63 - 20 = 43 = 17 mod 26
 * 
 * Invertibility Condition:
 *   gcd(det(K), 26) = gcd(17, 26) = 1 (Invertible)
 * 
 * Modular Inverse of Determinant:
 *   17 * d^{-1} = 1 mod 26 -> d^{-1} = 23 (since 17 * 23 = 391 = 15 * 26 + 1)
 * 
 * Inverse Key Matrix K^{-1}:
 *   adj(K) = [  k22  -k12 ] = [  7  -4 ] = [  7  22 ] mod 26
 *            [ -k21   k11 ]   [ -5   9 ]   [ 21   9 ]
 *   K^{-1} = 23 * adj(K) mod 26
 *   K^{-1} = [ 161  506 ] = [  5  12 ] mod 26
 *            [ 483  207 ]   [ 15  25 ]
 * 
 * Vector Convention: Column Vectors
 *   Encryption: [C1, C2]^T = K * [P1, P2]^T mod 26
 *   Decryption: [P1, P2]^T = K^{-1} * [C1, C2]^T mod 26
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_LEN 2048

int gcd(int a, int b) {
    while (b != 0) {
        int t = b;
        b = a % b;
        a = t;
    }
    return a;
}

int mod_inverse(int a, int m) {
    a = (a % m + m) % m;
    int m0 = m, t, q;
    int x0 = 0, x1 = 1;

    if (m == 1) return 0;
    while (a > 1) {
        if (m == 0) return -1;
        q = a / m;
        t = m;
        m = a % m;
        a = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }
    if (x1 < 0) x1 += m0;
    return x1;
}

int compute_inverse_matrix_2x2(int K[2][2], int K_inv[2][2]) {
    int det = (K[0][0] * K[1][1] - K[0][1] * K[1][0]) % 26;
    if (det < 0) det += 26;

    int g = gcd(det, 26);
    if (g != 1) {
        return 0; // Not invertible mod 26
    }

    int inv_det = mod_inverse(det, 26);

    // adj(K) = [ K[1][1], -K[0][1]; -K[1][0], K[0][0] ]
    int adj[2][2];
    adj[0][0] = (K[1][1] % 26 + 26) % 26;
    adj[0][1] = (-K[0][1] % 26 + 26) % 26;
    adj[1][0] = (-K[1][0] % 26 + 26) % 26;
    adj[1][1] = (K[0][0] % 26 + 26) % 26;

    for (int r = 0; r < 2; r++) {
        for (int c = 0; c < 2; c++) {
            K_inv[r][c] = (inv_det * adj[r][c]) % 26;
        }
    }
    return 1;
}

void hill_encrypt(const int K[2][2], const char *clean_pt, char *ct) {
    int len = (int)strlen(clean_pt);
    for (int i = 0; i < len; i += 2) {
        int p1 = clean_pt[i] - 'A';
        int p2 = clean_pt[i + 1] - 'A';

        int c1 = (K[0][0] * p1 + K[0][1] * p2) % 26;
        int c2 = (K[1][0] * p1 + K[1][1] * p2) % 26;

        ct[i] = (char)(c1 + 'A');
        ct[i + 1] = (char)(c2 + 'A');
    }
    ct[len] = '\0';
}

void hill_decrypt(const int K_inv[2][2], const char *ct, char *recovered_pt) {
    int len = (int)strlen(ct);
    for (int i = 0; i < len; i += 2) {
        int c1 = ct[i] - 'A';
        int c2 = ct[i + 1] - 'A';

        int p1 = (K_inv[0][0] * c1 + K_inv[0][1] * c2) % 26;
        int p2 = (K_inv[1][0] * c1 + K_inv[1][1] * c2) % 26;

        recovered_pt[i] = (char)(p1 + 'A');
        recovered_pt[i + 1] = (char)(p2 + 'A');
    }
    recovered_pt[len] = '\0';
}

int main(void) {
    int K[2][2] = {
        {9, 4},
        {5, 7}
    };
    int K_inv[2][2];

    const char *raw_plaintext = "meet me at the usual place at ten rather than eight oclock";

    printf("=================================================================\n");
    printf("     EXPERIMENT 12: HILL CIPHER ENCRYPTION AND DECRYPTION        \n");
    printf("=================================================================\n\n");

    printf("KEY MATRIX (K):\n");
    printf("   [ %2d  %2d ]\n", K[0][0], K[0][1]);
    printf("   [ %2d  %2d ]\n\n", K[1][0], K[1][1]);

    int det = (K[0][0] * K[1][1] - K[0][1] * K[1][0]) % 26;
    if (det < 0) det += 26;
    int det_inv = mod_inverse(det, 26);

    printf("MATHEMATICAL INVERTIBILITY CHECK:\n");
    printf("-----------------------------------------------------------------\n");
    printf("Determinant det(K)     : (9*7 - 4*5) = 43 = %d (mod 26)\n", det);
    printf("Coprime Check          : gcd(%d, 26) = %d -> VALID\n", det, gcd(det, 26));
    printf("Modular Inverse det^-1 : %d  [(%d * %d) mod 26 = %d]\n\n", det_inv, det, det_inv, (det * det_inv) % 26);

    if (!compute_inverse_matrix_2x2(K, K_inv)) {
        printf("[-] Error: Key matrix is not invertible modulo 26.\n");
        return 1;
    }

    printf("INVERSE KEY MATRIX (K^-1 mod 26):\n");
    printf("   [ %2d  %2d ]\n", K_inv[0][0], K_inv[0][1]);
    printf("   [ %2d  %2d ]\n\n", K_inv[1][0], K_inv[1][1]);

    // Normalize plaintext (uppercase, alphabetic only)
    char clean_pt[MAX_LEN];
    int pt_len = 0;
    for (int i = 0; raw_plaintext[i] != '\0'; i++) {
        if (isalpha((unsigned char)raw_plaintext[i])) {
            clean_pt[pt_len++] = (char)toupper((unsigned char)raw_plaintext[i]);
        }
    }
    // Pad with 'X' if odd length
    if (pt_len % 2 != 0) {
        clean_pt[pt_len++] = 'X';
    }
    clean_pt[pt_len] = '\0';

    char ciphertext[MAX_LEN];
    char recovered[MAX_LEN];

    hill_encrypt(K, clean_pt, ciphertext);
    hill_decrypt(K_inv, ciphertext, recovered);

    printf("-----------------------------------------------------------------\n");
    printf("RESULTS & VERIFICATION:\n");
    printf("-----------------------------------------------------------------\n");
    printf("Original Input      : \"%s\"\n", raw_plaintext);
    printf("Normalized Plaintext: %s (length: %d)\n\n", clean_pt, pt_len);

    printf("Encrypted Ciphertext (Digraphs):\n  ");
    for (int i = 0; i < pt_len; i += 2) {
        printf("%c%c ", ciphertext[i], ciphertext[i + 1]);
    }
    printf("\n\nCiphertext (Continuous):\n  %s\n\n", ciphertext);

    printf("Decrypted Plaintext :\n  %s\n\n", recovered);

    if (strcmp(clean_pt, recovered) == 0) {
        printf("[+] Verification SUCCESS: 100%% exact round-trip decryption achieved.\n");
    } else {
        printf("[-] Verification FAILED: Decrypted text does not match.\n");
    }
    printf("=================================================================\n");

    return 0;
}
