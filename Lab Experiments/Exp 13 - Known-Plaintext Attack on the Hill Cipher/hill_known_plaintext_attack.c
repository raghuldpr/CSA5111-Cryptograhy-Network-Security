/*
 * Experiment 13: Known-Plaintext Attack on the Hill Cipher
 * 
 * Cryptanalytic Principle (2x2 Hill Cipher):
 * Column Vector Convention:
 *   For each 2x1 plaintext column vector P_i and ciphertext column vector C_i:
 *     C_i = K * P_i (mod 26)
 * 
 * If an attacker intercepts two independent plaintext-ciphertext pairs:
 *   Pair 1: P_1 = [p11, p21]^T  ->  C_1 = [c11, c21]^T
 *   Pair 2: P_2 = [p12, p22]^T  ->  C_2 = [c12, c22]^T
 * 
 * Constructing 2x2 matrices:
 *   P = [ P_1 | P_2 ] = [ p11  p12 ]
 *                       [ p21  p22 ]
 *   C = [ C_1 | C_2 ] = [ c11  c12 ]
 *                       [ c21  c22 ]
 * 
 * The system satisfies the matrix relation:
 *   C = K * P (mod 26)
 * 
 * Multiplying both sides by P^{-1} on the right:
 *   K = C * P^{-1} (mod 26)
 * 
 * Invertibility Requirement:
 *   The attack succeeds if and only if P is invertible modulo 26, which requires:
 *     gcd(det(P), 26) = 1
 *   If gcd(det(P), 26) != 1, the chosen pair does not yield a unique key, and
 *   the analyst must select alternative known pairs whose determinant is coprime to 26.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

int invert_matrix_2x2(int M[2][2], int M_inv[2][2]) {
    int det = (M[0][0] * M[1][1] - M[0][1] * M[1][0]) % 26;
    if (det < 0) det += 26;

    int g = gcd(det, 26);
    if (g != 1) {
        return 0; // Not invertible
    }

    int inv_det = mod_inverse(det, 26);
    int adj[2][2];
    adj[0][0] = (M[1][1] % 26 + 26) % 26;
    adj[0][1] = (-M[0][1] % 26 + 26) % 26;
    adj[1][0] = (-M[1][0] % 26 + 26) % 26;
    adj[1][1] = (M[0][0] % 26 + 26) % 26;

    for (int r = 0; r < 2; r++) {
        for (int c = 0; c < 2; c++) {
            M_inv[r][c] = (inv_det * adj[r][c]) % 26;
        }
    }
    return 1;
}

void multiply_matrices_2x2(int A[2][2], int B[2][2], int Out[2][2]) {
    for (int r = 0; r < 2; r++) {
        for (int c = 0; c < 2; c++) {
            Out[r][c] = (A[r][0] * B[0][c] + A[r][1] * B[1][c]) % 26;
        }
    }
}

int main(void) {
    printf("=================================================================\n");
    printf("     EXPERIMENT 13: KNOWN-PLAINTEXT ATTACK ON THE HILL CIPHER    \n");
    printf("=================================================================\n\n");

    printf("1. THEORETICAL FORMULATION:\n");
    printf("   Column vector convention: C = K * P mod 26\n");
    printf("   Multiplying by P^-1     : K = C * P^-1 mod 26\n\n");

    // Case 1: Non-invertible pair demonstration
    printf("2. CASE STUDY A: TESTING ADJACENT BLOCKS ('me' and 'et')\n");
    printf("-----------------------------------------------------------------\n");
    int P_fail[2][2] = {
        {12,  4},  // 'm' (12), 'e' (4)
        { 4, 19}   // 'e' (4),  't' (19)
    };
    int det_fail = (P_fail[0][0] * P_fail[1][1] - P_fail[0][1] * P_fail[1][0]) % 26;
    if (det_fail < 0) det_fail += 26;

    printf("   Plaintext Matrix P:\n");
    printf("      [ %2d ('m')   %2d ('e') ]\n", P_fail[0][0], P_fail[0][1]);
    printf("      [ %2d ('e')   %2d ('t') ]\n", P_fail[1][0], P_fail[1][1]);
    printf("   det(P) = (12*19 - 4*4) mod 26 = %d\n", det_fail);
    printf("   gcd(det(P), 26) = %d\n", gcd(det_fail, 26));
    printf("   [-] RESULT: gcd != 1. Matrix P is NOT invertible modulo 26!\n");
    printf("       The attack cannot recover the key from these pairs.\n\n");

    // Case 2: Invertible pair demonstration from known cipher pairs
    // From Experiment 12 with true K = [9, 4; 5, 7]:
    // Pair 1: 'et' = [4, 19]^T  -> C1 = [8, 23]^T ('IX')
    // Pair 2: 'th' = [19, 7]^T  -> C2 = [17, 14]^T ('RO')
    printf("3. CASE STUDY B: SELECTING INVERTIBLE BLOCKS ('et' and 'th')\n");
    printf("-----------------------------------------------------------------\n");
    int P_valid[2][2] = {
        { 4, 19},  // 'e' (4),  't' (19)
        {19,  7}   // 't' (19), 'h' (7)
    };
    int C_valid[2][2] = {
        { 8, 17},  // 'I' (8),  'R' (17)
        {23, 14}   // 'X' (23), 'O' (14)
    };

    printf("   Known Plaintext Pairs : ('et' -> [4, 19]^T) and ('th' -> [19, 7]^T)\n");
    printf("   Intercepted Ciphertext: ('IX' -> [8, 23]^T) and ('RO' -> [17, 14]^T)\n\n");

    printf("   Plaintext Matrix (P):\n");
    printf("      [ %2d  %2d ]\n", P_valid[0][0], P_valid[0][1]);
    printf("      [ %2d  %2d ]\n", P_valid[1][0], P_valid[1][1]);

    printf("   Ciphertext Matrix (C):\n");
    printf("      [ %2d  %2d ]\n", C_valid[0][0], C_valid[0][1]);
    printf("      [ %2d  %2d ]\n\n", C_valid[1][0], C_valid[1][1]);

    int det_valid = (P_valid[0][0] * P_valid[1][1] - P_valid[0][1] * P_valid[1][0]) % 26;
    if (det_valid < 0) det_valid += 26;
    int det_valid_inv = mod_inverse(det_valid, 26);

    printf("   det(P) = (4*7 - 19*19) mod 26 = %d\n", det_valid);
    printf("   gcd(%d, 26) = %d -> INVERTIBLE!\n", det_valid, gcd(det_valid, 26));
    printf("   det(P)^-1 mod 26 = %d\n\n", det_valid_inv);

    int P_inv[2][2];
    if (!invert_matrix_2x2(P_valid, P_inv)) {
        printf("[-] Inversion failed unexpected.\n");
        return 1;
    }

    printf("   Calculated P^-1 (mod 26):\n");
    printf("      [ %2d  %2d ]\n", P_inv[0][0], P_inv[0][1]);
    printf("      [ %2d  %2d ]\n\n", P_inv[1][0], P_inv[1][1]);

    int K_recovered[2][2];
    multiply_matrices_2x2(C_valid, P_inv, K_recovered);

    printf("4. RECOVERED SECRET KEY MATRIX (K = C * P^-1 mod 26):\n");
    printf("-----------------------------------------------------------------\n");
    printf("   K_recovered =\n");
    printf("      [ %2d  %2d ]\n", K_recovered[0][0], K_recovered[0][1]);
    printf("      [ %2d  %2d ]\n\n", K_recovered[1][0], K_recovered[1][1]);

    // Verification check against known pairs
    int check1_0 = (K_recovered[0][0] * 4 + K_recovered[0][1] * 19) % 26;
    int check1_1 = (K_recovered[1][0] * 4 + K_recovered[1][1] * 19) % 26;
    int check2_0 = (K_recovered[0][0] * 19 + K_recovered[0][1] * 7) % 26;
    int check2_1 = (K_recovered[1][0] * 19 + K_recovered[1][1] * 7) % 26;

    printf("5. VERIFICATION OF RECOVERED KEY ON SAMPLE PAIRS:\n");
    printf("-----------------------------------------------------------------\n");
    printf("   K * [ 4, 19]^T = [ %2d, %2d ]^T (Expected: [ 8, 23]^T) -> %s\n",
           check1_0, check1_1, (check1_0 == 8 && check1_1 == 23) ? "MATCH" : "MISMATCH");
    printf("   K * [19,  7]^T = [ %2d, %2d ]^T (Expected: [17, 14]^T) -> %s\n",
           check2_0, check2_1, (check2_0 == 17 && check2_1 == 14) ? "MATCH" : "MISMATCH");

    if (K_recovered[0][0] == 9 && K_recovered[0][1] == 4 &&
        K_recovered[1][0] == 5 && K_recovered[1][1] == 7) {
        printf("\n[+] Verification SUCCESS: Secret key K = [9, 4; 5, 7] exactly recovered.\n");
    } else {
        printf("\n[-] Verification FAILED: Incorrect key recovered.\n");
    }
    printf("=================================================================\n");

    return 0;
}
