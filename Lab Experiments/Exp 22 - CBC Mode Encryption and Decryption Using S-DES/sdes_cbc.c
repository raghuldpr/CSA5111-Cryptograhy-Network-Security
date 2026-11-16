/*
 * ============================================================================
 * Experiment 22: CBC Mode Encryption and Decryption Using S-DES
 * 
 * Objective:
 *   Implement Simplified Data Encryption Standard (S-DES) in C and demonstrate
 *   Cipher Block Chaining (CBC) mode encryption and decryption.
 * 
 * CBC Mode Formulations:
 *   Encryption:
 *     C[0] = E(K, P[0] XOR IV)
 *     C[i] = E(K, P[i] XOR C[i-1]) for i >= 1
 * 
 *   Decryption:
 *     P[0] = D(K, C[0]) XOR IV
 *     P[i] = D(K, C[i]) XOR C[i-1] for i >= 1
 * 
 * S-DES Specifications (Stallings / Schaefer):
 *   - Key Size   : 10 bits -> generates two 8-bit subkeys (K1, K2)
 *   - Block Size : 8 bits
 *   - Rounds     : 2 Feistel rounds with swapping
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BITS 1024

// S-DES Permutation and Expansion Tables (1-based indices)
static const int P10[10] = {3, 5, 2, 7, 4, 10, 1, 9, 8, 6};
static const int P8[8]   = {6, 3, 7, 4, 8, 5, 10, 9};
static const int IP[8]   = {2, 6, 3, 1, 4, 8, 5, 7};
static const int IP_INV[8] = {4, 1, 3, 5, 7, 2, 8, 6};
static const int EP[8]   = {4, 1, 2, 3, 2, 3, 4, 1};
static const int P4[4]   = {2, 4, 3, 1};

// S-DES S-Boxes
static const int S0[4][4] = {
    {1, 0, 3, 2},
    {3, 2, 1, 0},
    {0, 2, 1, 3},
    {3, 1, 3, 2}
};

static const int S1[4][4] = {
    {0, 1, 2, 3},
    {2, 0, 1, 3},
    {3, 0, 1, 0},
    {2, 1, 0, 3}
};

// Permutes an input bit array into an output bit array using given table
void permute(const int *in, int *out, const int *table, int size) {
    for (int i = 0; i < size; i++) {
        out[i] = in[table[i] - 1];
    }
}

// Circular left shift on a 5-bit array
void left_shift(const int *in, int *out, int shift) {
    for (int i = 0; i < 5; i++) {
        out[i] = in[(i + shift) % 5];
    }
}

// Key generation: generates K1 and K2 from a 10-bit raw key
void generate_subkeys(const int *key, int *k1, int *k2) {
    int p10[10];
    permute(key, p10, P10, 10);

    int l0[5], r0[5];
    for (int i = 0; i < 5; i++) {
        l0[i] = p10[i];
        r0[i] = p10[i + 5];
    }

    // Round 1: LS-1
    int l1[5], r1[5];
    left_shift(l0, l1, 1);
    left_shift(r0, r1, 1);

    int combined1[10];
    for (int i = 0; i < 5; i++) {
        combined1[i] = l1[i];
        combined1[i + 5] = r1[i];
    }
    permute(combined1, k1, P8, 8);

    // Round 2: LS-2 (applied to l1, r1)
    int l2[5], r2[5];
    left_shift(l1, l2, 2);
    left_shift(r1, r2, 2);

    int combined2[10];
    for (int i = 0; i < 5; i++) {
        combined2[i] = l2[i];
        combined2[i + 5] = r2[i];
    }
    permute(combined2, k2, P8, 8);
}

// Round function fk: fk(L, R, K) = (L XOR F(R, K), R)
void fk(const int *in, const int *subkey, int *out) {
    int left[4], right[4];
    for (int i = 0; i < 4; i++) {
        left[i] = in[i];
        right[i] = in[i + 4];
    }

    // Expansion / Permutation E/P on right 4 bits
    int ep[8];
    permute(right, ep, EP, 8);

    // XOR with subkey
    int xor_res[8];
    for (int i = 0; i < 8; i++) {
        xor_res[i] = ep[i] ^ subkey[i];
    }

    // S-Box lookups
    int r0 = (xor_res[0] << 1) | xor_res[3];
    int c0 = (xor_res[1] << 1) | xor_res[2];
    int val0 = S0[r0][c0];

    int r1 = (xor_res[4] << 1) | xor_res[7];
    int c1 = (xor_res[5] << 1) | xor_res[6];
    int val1 = S1[r1][c1];

    int s_out[4];
    s_out[0] = (val0 >> 1) & 1;
    s_out[1] = val0 & 1;
    s_out[2] = (val1 >> 1) & 1;
    s_out[3] = val1 & 1;

    // Permutation P4
    int p4[4];
    permute(s_out, p4, P4, 4);

    // Left XOR P4
    for (int i = 0; i < 4; i++) {
        out[i] = left[i] ^ p4[i];
        out[i + 4] = right[i];
    }
}

// Encrypts an 8-bit block with S-DES using subkeys K1, K2
void sdes_encrypt_block(const int *plain, const int *k1, const int *k2, int *cipher) {
    int ip[8];
    permute(plain, ip, IP, 8);

    int r1[8];
    fk(ip, k1, r1);

    // Swap halves (SW)
    int sw[8];
    for (int i = 0; i < 4; i++) {
        sw[i] = r1[i + 4];
        sw[i + 4] = r1[i];
    }

    int r2[8];
    fk(sw, k2, r2);

    permute(r2, cipher, IP_INV, 8);
}

// Decrypts an 8-bit block with S-DES using subkeys K2, K1
void sdes_decrypt_block(const int *cipher, const int *k1, const int *k2, int *plain) {
    int ip[8];
    permute(cipher, ip, IP, 8);

    // Decryption applies K2 in round 1
    int r1[8];
    fk(ip, k2, r1);

    // Swap halves (SW)
    int sw[8];
    for (int i = 0; i < 4; i++) {
        sw[i] = r1[i + 4];
        sw[i + 4] = r1[i];
    }

    // Decryption applies K1 in round 2
    int r2[8];
    fk(sw, k1, r2);

    permute(r2, plain, IP_INV, 8);
}

void print_bits(const int *bits, int size) {
    for (int i = 0; i < size; i++) {
        putchar(bits[i] ? '1' : '0');
    }
}

int parse_bits(const char *str, int *bits, int expected_len) {
    int len = strlen(str);
    if (expected_len > 0 && len != expected_len) return 0;
    for (int i = 0; i < len; i++) {
        if (str[i] != '0' && str[i] != '1') return 0;
        bits[i] = str[i] - '0';
    }
    return len;
}

int main(void) {
    char key_str[64];
    char iv_str[64];
    char pt_str[MAX_BITS];

    int key[10];
    int iv[8];
    int pt[MAX_BITS];
    int ct[MAX_BITS];
    int recovered_pt[MAX_BITS];
    int k1[8], k2[8];

    printf("====================================================================\n");
    printf("   EXP 22: CBC MODE ENCRYPTION & DECRYPTION USING S-DES            \n");
    printf("====================================================================\n\n");

    // 1. Inputs
    printf("Enter 10-bit binary key (e.g., 0111111101): ");
    if (scanf("%63s", key_str) != 1 || !parse_bits(key_str, key, 10)) {
        printf("Error: Key must be exactly 10 binary digits.\n");
        return 1;
    }

    printf("Enter 8-bit binary IV   (e.g., 10101010)  : ");
    if (scanf("%63s", iv_str) != 1 || !parse_bits(iv_str, iv, 8)) {
        printf("Error: IV must be exactly 8 binary digits.\n");
        return 1;
    }

    printf("Enter binary plaintext  (e.g., 0000000100100011): ");
    if (scanf("%1023s", pt_str) != 1) {
        printf("Error: Failed to read plaintext.\n");
        return 1;
    }

    int pt_len = parse_bits(pt_str, pt, -1);
    if (pt_len <= 0 || (pt_len % 8) != 0) {
        printf("Error: Plaintext length must be a non-zero multiple of 8 bits.\n");
        return 1;
    }

    int num_blocks = pt_len / 8;

    // 2. Generate subkeys
    generate_subkeys(key, k1, k2);

    printf("\n--------------------------------------------------------------------\n");
    printf("KEY SCHEDULE & PARAMETERS:\n");
    printf("--------------------------------------------------------------------\n");
    printf("Master Key (10 bits) : "); print_bits(key, 10); printf("\n");
    printf("Subkey K1  (8 bits)  : "); print_bits(k1, 8);   printf("\n");
    printf("Subkey K2  (8 bits)  : "); print_bits(k2, 8);   printf("\n");
    printf("Initialization Vector: "); print_bits(iv, 8);   printf("\n");
    printf("Plaintext Blocks     : %d block(s) (%d bits)\n", num_blocks, pt_len);

    // 3. CBC Encryption
    printf("\n--------------------------------------------------------------------\n");
    printf("CBC MODE ENCRYPTION:\n");
    printf("Formula: C[i] = E(K, P[i] XOR (i == 0 ? IV : C[i-1]))\n");
    printf("--------------------------------------------------------------------\n");

    int prev_block[8];
    for (int i = 0; i < 8; i++) prev_block[i] = iv[i];

    for (int b = 0; b < num_blocks; b++) {
        int *current_p = &pt[b * 8];
        int *current_c = &ct[b * 8];
        int xor_in[8];

        for (int i = 0; i < 8; i++) {
            xor_in[i] = current_p[i] ^ prev_block[i];
        }

        sdes_encrypt_block(xor_in, k1, k2, current_c);

        printf("Block %d:\n", b + 1);
        printf("  P[%d]             : ", b); print_bits(current_p, 8); printf("\n");
        printf("  Feedback (%s) : ", (b == 0) ? "IV  " : "C-prev"); print_bits(prev_block, 8); printf("\n");
        printf("  P[%d] XOR Feedbk : ", b); print_bits(xor_in, 8); printf("\n");
        printf("  C[%d] (Encrypted) : ", b); print_bits(current_c, 8); printf("\n");

        for (int i = 0; i < 8; i++) prev_block[i] = current_c[i];
    }

    printf("\n--> Full Ciphertext: ");
    print_bits(ct, pt_len);
    printf("\n");

    // 4. CBC Decryption
    printf("\n--------------------------------------------------------------------\n");
    printf("CBC MODE DECRYPTION:\n");
    printf("Formula: P[i] = D(K, C[i]) XOR (i == 0 ? IV : C[i-1])\n");
    printf("--------------------------------------------------------------------\n");

    for (int i = 0; i < 8; i++) prev_block[i] = iv[i];

    for (int b = 0; b < num_blocks; b++) {
        int *current_c = &ct[b * 8];
        int *current_p = &recovered_pt[b * 8];
        int decrypted_raw[8];

        sdes_decrypt_block(current_c, k1, k2, decrypted_raw);

        for (int i = 0; i < 8; i++) {
            current_p[i] = decrypted_raw[i] ^ prev_block[i];
        }

        printf("Block %d:\n", b + 1);
        printf("  C[%d]             : ", b); print_bits(current_c, 8); printf("\n");
        printf("  D(K, C[%d])       : ", b); print_bits(decrypted_raw, 8); printf("\n");
        printf("  Feedback (%s) : ", (b == 0) ? "IV  " : "C-prev"); print_bits(prev_block, 8); printf("\n");
        printf("  P[%d] (Recovered) : ", b); print_bits(current_p, 8); printf("\n");

        for (int i = 0; i < 8; i++) prev_block[i] = current_c[i];
    }

    printf("\n--> Recovered Plaintext : ");
    print_bits(recovered_pt, pt_len);
    printf("\n");

    // 5. Verification
    int matches = 1;
    for (int i = 0; i < pt_len; i++) {
        if (pt[i] != recovered_pt[i]) {
            matches = 0;
            break;
        }
    }

    printf("\n====================================================================\n");
    printf("VERIFICATION RESULT:\n");
    printf("====================================================================\n");
    if (matches) {
        printf("[SUCCESS] Decrypted plaintext matches the original plaintext exactly!\n");
    } else {
        printf("[FAILED] Decrypted plaintext does not match original plaintext!\n");
    }
    printf("====================================================================\n");

    return 0;
}
