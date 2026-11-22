/*
 * ============================================================================
 * Experiment 38: Known-Plaintext & Chosen-Plaintext Attack on Hill Cipher
 *
 * Objective:
 *   Demonstrate cryptanalysis of a 2x2 Hill Cipher modulo 26 using both:
 *     1. Known-Plaintext Attack (KPA) via modular matrix inversion:
 *        K = C * P^(-1) mod 26
 *     2. Chosen-Plaintext Attack (CPA) using unit/identity basis vectors:
 *        P = I -> C = K * I = K mod 26
 *
 * Mathematical Foundations:
 *   Encryption Convention (Column Vector Representation):
 *     c_i = K * p_i mod 26
 *     For two plaintext-ciphertext block pairs (p1, c1) and (p2, c2):
 *     [c1 c2] = K * [p1 p2] mod 26  ==>  C = K * P mod 26
 *
 *   1. Known-Plaintext Attack (KPA):
 *      - Given matrices P and C formed by known blocks:
 *      - Compute determinant: det(P) = (p00*p11 - p01*p10) mod 26
 *      - Verify gcd(det(P), 26) == 1 (invertibility check)
 *      - Compute modular inverse: det_inv = det(P)^(-1) mod 26
 *      - Compute adjugate matrix:
 *        adj(P) = [ p11   -p01 ]
 *                 [-p10    p00 ] mod 26
 *      - Invert P: P^(-1) = det_inv * adj(P) mod 26
 *      - Recover Key Matrix: K = C * P^(-1) mod 26
 *      - Verify: Check K * p_i mod 26 == c_i
 *
 *   2. Chosen-Plaintext Attack (CPA):
 *      - Attacker chooses specific plaintexts. Choosing the standard basis:
 *        p1 = [1, 0]^T ("BA")
 *        p2 = [0, 1]^T ("AB")
 *        forms the Identity Matrix P = I = [[1, 0], [0, 1]].
 *      - The resulting ciphertext matrix directly yields:
 *        C = K * I = K mod 26
 *      - CPA requires zero matrix inversion, zero determinant checks, and is
 *        strictly more powerful and trivial than KPA.
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>

// Computes GCD using Euclidean Algorithm
int gcd(int a, int b) {
    while (b != 0) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

// Computes modular inverse using Extended Euclidean Algorithm
int mod_inverse(int a, int m) {
    int m0 = m;
    int y = 0, x = 1;

    if (gcd(a, m) != 1) return -1;
    if (m == 1) return 0;

    a = (a % m + m) % m;

    while (a > 1) {
        int q = a / m;
        int t = m;
        m = a % m;
        a = t;
        t = y;
        y = x - q * y;
        x = t;
    }

    if (x < 0) x += m0;
    return x;
}

// Multiplies two 2x2 matrices modulo 26: R = (A * B) mod 26
void mat_mul2(const int A[2][2], const int B[2][2], int R[2][2]) {
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 2; j++) {
            int sum = 0;
            for (int k = 0; k < 2; k++) {
                sum += A[i][k] * B[k][j];
            }
            R[i][j] = (sum % 26 + 26) % 26;
        }
    }
}

// Inverts a 2x2 matrix modulo 26: Inv = det^(-1) * adj(M) mod 26
int mat_inv2(const int M[2][2], int Inv[2][2], int *det_out, int *det_inv_out) {
    int det = (M[0][0] * M[1][1] - M[0][1] * M[1][0]) % 26;
    det = (det % 26 + 26) % 26;
    *det_out = det;

    if (gcd(det, 26) != 1) {
        *det_inv_out = -1;
        return 0; // Not invertible
    }

    int det_inv = mod_inverse(det, 26);
    *det_inv_out = det_inv;

    // Adjugate matrix
    int adj[2][2];
    adj[0][0] = (M[1][1] % 26 + 26) % 26;
    adj[0][1] = (-M[0][1] % 26 + 26) % 26;
    adj[1][0] = (-M[1][0] % 26 + 26) % 26;
    adj[1][1] = (M[0][0] % 26 + 26) % 26;

    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 2; j++) {
            Inv[i][j] = (det_inv * adj[i][j]) % 26;
        }
    }

    return 1;
}

// Prints a 2x2 matrix
void print_matrix(const char *name, const int M[2][2]) {
    printf("  %s = [ [ %2d, %2d ],\n", name, M[0][0], M[0][1]);
    printf("        [ %2d, %2d ] ] (mod 26)\n", M[1][0], M[1][1]);
}

int main(void) {
    // Secret Key Matrix K:
    // [ [ 9, 4 ],
    //   [ 5, 7 ] ]
    int K_secret[2][2] = {
        {9, 4},
        {5, 7}
    };

    // Known Plaintext Matrix P:
    // Block 1: [3, 2]^T ("DC"), Block 2: [8, 5]^T ("IF")
    // P = [ [3, 8], [2, 5] ]
    int P[2][2] = {
        {3, 8},
        {2, 5}
    };

    int C[2][2];
    int P_inv[2][2];
    int K_recovered[2][2];
    int det_P, det_inv_P;

    printf("====================================================================\n");
    printf("    EXPERIMENT 38: KNOWN-PLAINTEXT & CHOSEN-PLAINTEXT ATTACK       \n");
    printf("                     ON 2x2 HILL CIPHER                            \n");
    printf("====================================================================\n\n");

    printf("Secret 2x2 Key Matrix to be recovered by attacker:\n");
    print_matrix("K_secret", K_secret);

    // Compute Ciphertext Matrix C = K_secret * P mod 26
    mat_mul2(K_secret, P, C);

    // -------------------------------------------------------------------------
    // PART 1: KNOWN-PLAINTEXT ATTACK (KPA)
    // -------------------------------------------------------------------------
    printf("\n====================================================================\n");
    printf("              PART 1: KNOWN-PLAINTEXT ATTACK (KPA)                  \n");
    printf("====================================================================\n");
    printf("Attacker knows 2 plaintext-ciphertext pairs (column vectors):\n");
    printf("  Pair 1: Plaintext [ %d, %d ]^T (\"DC\") -> Ciphertext [ %d, %d ]^T (\"JD\")\n",
           P[0][0], P[1][0], C[0][0], C[1][0]);
    printf("  Pair 2: Plaintext [ %d, %d ]^T (\"IF\") -> Ciphertext [ %d, %d ]^T (\"OX\")\n",
           P[0][1], P[1][1], C[0][1], C[1][1]);

    printf("\nForming Matrices P and C:\n");
    print_matrix("P", P);
    print_matrix("C", C);

    printf("\n[*] Step 1: Calculate determinant of Plaintext Matrix P:\n");
    printf("    det(P) = (p00 * p11 - p01 * p10) mod 26\n");
    printf("           = (%d * %d - %d * %d) mod 26\n",
           P[0][0], P[1][1], P[0][1], P[1][0]);

    if (!mat_inv2(P, P_inv, &det_P, &det_inv_P)) {
        printf("[ERROR] det(P) = %d shares common factor with 26 (gcd = %d).\n",
               det_P, gcd(det_P, 26));
        printf("        P is singular mod 26; choose different known blocks.\n");
        return 1;
    }

    printf("           = %d mod 26\n", det_P);
    printf("    gcd(det(P), 26) = gcd(%d, 26) = 1 [INVERTIBLE]\n", det_P);
    printf("    Modular Inverse of det(P): det(P)^(-1) mod 26 = %d\n", det_inv_P);

    printf("\n[*] Step 2: Compute P^(-1) mod 26:\n");
    print_matrix("P^(-1)", P_inv);

    // Verify P * P^(-1) == I mod 26
    int I_check[2][2];
    mat_mul2(P, P_inv, I_check);
    printf("    Check P * P^(-1) mod 26:\n");
    print_matrix("I_check", I_check);

    printf("\n[*] Step 3: Recover Key Matrix K = C * P^(-1) mod 26:\n");
    mat_mul2(C, P_inv, K_recovered);
    print_matrix("K_recovered", K_recovered);

    // Verification
    int verify_C[2][2];
    mat_mul2(K_recovered, P, verify_C);
    printf("\n[*] Step 4: Verify recovered key by re-encrypting P:\n");
    print_matrix("K_recovered * P", verify_C);

    if (verify_C[0][0] == C[0][0] && verify_C[0][1] == C[0][1] &&
        verify_C[1][0] == C[1][0] && verify_C[1][1] == C[1][1]) {
        printf("[VERIFIED] Recovered key perfectly matches C and secret key K!\n");
    }

    // -------------------------------------------------------------------------
    // PART 2: CHOSEN-PLAINTEXT ATTACK (CPA)
    // -------------------------------------------------------------------------
    printf("\n====================================================================\n");
    printf("             PART 2: CHOSEN-PLAINTEXT ATTACK (CPA)                  \n");
    printf("====================================================================\n");
    printf("In a Chosen-Plaintext Attack, the attacker submits chosen vectors:\n");
    printf("  Chosen Block 1: p1 = [ 1, 0 ]^T ('B', 'A')\n");
    printf("  Chosen Block 2: p2 = [ 0, 1 ]^T ('A', 'B')\n");
    printf("  This constructs the Identity Matrix: P_chosen = I = [ [1, 0], [0, 1] ]\n\n");

    int P_chosen[2][2] = {{1, 0}, {0, 1}};
    int C_chosen[2][2];
    mat_mul2(K_secret, P_chosen, C_chosen);

    print_matrix("P_chosen (I)", P_chosen);
    print_matrix("C_chosen (K * I)", C_chosen);

    printf("\nTheoretical Insight:\n");
    printf("  C_chosen = K * P_chosen = K * I = K (mod 26)\n");
    printf("  Result: The ciphertext directly outputs the secret key matrix:\n");
    printf("    Column 1 of C_chosen reveals Column 1 of Key: [ %d, %d ]^T\n",
           C_chosen[0][0], C_chosen[1][0]);
    printf("    Column 2 of C_chosen reveals Column 2 of Key: [ %d, %d ]^T\n",
           C_chosen[0][1], C_chosen[1][1]);

    printf("\nWhy CPA is easier than KPA:\n");
    printf("  1. In KPA, the attacker must find blocks where gcd(det(P), 26) == 1\n");
    printf("     and perform modular matrix inversion.\n");
    printf("  2. In CPA, by selecting the standard basis (Identity matrix), the key\n");
    printf("     is extracted immediately with zero computation or inversion.\n");
    printf("====================================================================\n");
    printf("[SUCCESS] Known-Plaintext and Chosen-Plaintext attacks demonstrated.\n");

    return 0;
}
