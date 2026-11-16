/*
 * ============================================================================
 * Experiment 23: Counter (CTR) Mode Encryption & Decryption Using S-DES
 * 
 * Objective:
 *   Implement Counter (CTR) mode operation using Simplified DES (S-DES).
 * 
 * CTR Mode Formulations:
 *   Encryption:
 *     O[i] = E(K, Counter[i])
 *     C[i] = P[i] XOR O[i]
 *     Counter[i+1] = (Counter[i] + 1) mod 256
 * 
 *   Decryption:
 *     O[i] = E(K, Counter[i])
 *     P[i] = C[i] XOR O[i]
 * 
 * Key Characteristic:
 *   In CTR mode, the underlying cipher function is ONLY used in the encryption
 *   direction E(K, ...) for both encryption AND decryption. Decryption does
 *   not require the cipher decryption function D(K, ...).
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BITS 1024

// S-DES Tables
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

// Permutes bits using table
void permute(const int *in, int *out, const int *table, int size) {
    for (int i = 0; i < size; i++) {
        out[i] = in[table[i] - 1];
    }
}

// Circular left shift on 5 bits
void left_shift(const int *in, int *out, int shift) {
    for (int i = 0; i < 5; i++) {
        out[i] = in[(i + shift) % 5];
    }
}

// Generates subkeys K1 and K2
void generate_subkeys(const int *key, int *k1, int *k2) {
    int p10[10];
    permute(key, p10, P10, 10);

    int l0[5], r0[5];
    for (int i = 0; i < 5; i++) {
        l0[i] = p10[i];
        r0[i] = p10[i + 5];
    }

    // Round 1
    int l1[5], r1[5];
    left_shift(l0, l1, 1);
    left_shift(r0, r1, 1);

    int combined1[10];
    for (int i = 0; i < 5; i++) {
        combined1[i] = l1[i];
        combined1[i + 5] = r1[i];
    }
    permute(combined1, k1, P8, 8);

    // Round 2
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

// Feistel round function
void fk(const int *in, const int *subkey, int *out) {
    int left[4], right[4];
    for (int i = 0; i < 4; i++) {
        left[i] = in[i];
        right[i] = in[i + 4];
    }

    int ep[8];
    permute(right, ep, EP, 8);

    int xor_res[8];
    for (int i = 0; i < 8; i++) {
        xor_res[i] = ep[i] ^ subkey[i];
    }

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

    int p4[4];
    permute(s_out, p4, P4, 4);

    for (int i = 0; i < 4; i++) {
        out[i] = left[i] ^ p4[i];
        out[i + 4] = right[i];
    }
}

// S-DES Block Encryption
void sdes_encrypt_block(const int *plain, const int *k1, const int *k2, int *cipher) {
    int ip[8];
    permute(plain, ip, IP, 8);

    int r1[8];
    fk(ip, k1, r1);

    int sw[8];
    for (int i = 0; i < 4; i++) {
        sw[i] = r1[i + 4];
        sw[i + 4] = r1[i];
    }

    int r2[8];
    fk(sw, k2, r2);

    permute(r2, cipher, IP_INV, 8);
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

// Converts integer value (0..255) to 8-bit binary array
void int_to_byte_bits(unsigned int val, int *bits) {
    for (int i = 7; i >= 0; i--) {
        bits[7 - i] = (val >> i) & 1;
    }
}

// Converts 8-bit binary array to integer value (0..255)
unsigned int byte_bits_to_int(const int *bits) {
    unsigned int val = 0;
    for (int i = 0; i < 8; i++) {
        val = (val << 1) | bits[i];
    }
    return val;
}

int main(void) {
    char key_str[64];
    char ctr_str[64];
    char pt_str[MAX_BITS];

    int key[10];
    int init_ctr_bits[8];
    int pt[MAX_BITS];
    int ct[MAX_BITS];
    int recovered_pt[MAX_BITS];
    int k1[8], k2[8];

    printf("====================================================================\n");
    printf("   EXP 23: CTR MODE ENCRYPTION & DECRYPTION USING S-DES            \n");
    printf("====================================================================\n\n");

    // 1. Inputs
    printf("Enter 10-bit binary key     (e.g., 0111111101): ");
    if (scanf("%63s", key_str) != 1 || !parse_bits(key_str, key, 10)) {
        printf("Error: Key must be exactly 10 binary digits.\n");
        return 1;
    }

    printf("Enter initial 8-bit counter (e.g., 00000000)  : ");
    if (scanf("%63s", ctr_str) != 1 || !parse_bits(ctr_str, init_ctr_bits, 8)) {
        printf("Error: Counter must be exactly 8 binary digits.\n");
        return 1;
    }

    printf("Enter binary plaintext (e.g., 000000010000001000000100): ");
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
    unsigned int initial_counter_val = byte_bits_to_int(init_ctr_bits);

    // 2. Generate subkeys
    generate_subkeys(key, k1, k2);

    printf("\n--------------------------------------------------------------------\n");
    printf("PARAMETERS & KEY SCHEDULE:\n");
    printf("--------------------------------------------------------------------\n");
    printf("Master Key (10 bits) : "); print_bits(key, 10); printf("\n");
    printf("Subkey K1  (8 bits)  : "); print_bits(k1, 8);   printf("\n");
    printf("Subkey K2  (8 bits)  : "); print_bits(k2, 8);   printf("\n");
    printf("Initial Counter      : "); print_bits(init_ctr_bits, 8); printf(" (decimal %u)\n", initial_counter_val);
    printf("Plaintext Blocks     : %d block(s) (%d bits)\n", num_blocks, pt_len);

    // 3. CTR Encryption
    printf("\n--------------------------------------------------------------------\n");
    printf("CTR MODE ENCRYPTION:\n");
    printf("Formula: C[i] = P[i] XOR E(K, Counter[i])\n");
    printf("--------------------------------------------------------------------\n");

    unsigned int current_ctr = initial_counter_val;

    for (int b = 0; b < num_blocks; b++) {
        int ctr_bits[8];
        int encrypted_ctr[8];
        int *current_p = &pt[b * 8];
        int *current_c = &ct[b * 8];

        int_to_byte_bits(current_ctr, ctr_bits);
        sdes_encrypt_block(ctr_bits, k1, k2, encrypted_ctr);

        for (int i = 0; i < 8; i++) {
            current_c[i] = current_p[i] ^ encrypted_ctr[i];
        }

        printf("Block %d (Counter = %u):\n", b + 1, current_ctr);
        printf("  Counter[%d]        : ", b); print_bits(ctr_bits, 8); printf("\n");
        printf("  E(K, Counter[%d])  : ", b); print_bits(encrypted_ctr, 8); printf("\n");
        printf("  P[%d]              : ", b); print_bits(current_p, 8); printf("\n");
        printf("  C[%d] (P XOR Enc) : ", b); print_bits(current_c, 8); printf("\n");

        current_ctr = (current_ctr + 1) % 256;
    }

    printf("\n--> Full Ciphertext: ");
    print_bits(ct, pt_len);
    printf("\n");

    // 4. CTR Decryption
    printf("\n--------------------------------------------------------------------\n");
    printf("CTR MODE DECRYPTION:\n");
    printf("Formula: P[i] = C[i] XOR E(K, Counter[i]) [Note: Uses Cipher Encrypt]\n");
    printf("--------------------------------------------------------------------\n");

    current_ctr = initial_counter_val;

    for (int b = 0; b < num_blocks; b++) {
        int ctr_bits[8];
        int encrypted_ctr[8];
        int *current_c = &ct[b * 8];
        int *current_p = &recovered_pt[b * 8];

        int_to_byte_bits(current_ctr, ctr_bits);
        // In CTR mode, decryption also calls ENCRYPTION of the counter!
        sdes_encrypt_block(ctr_bits, k1, k2, encrypted_ctr);

        for (int i = 0; i < 8; i++) {
            current_p[i] = current_c[i] ^ encrypted_ctr[i];
        }

        printf("Block %d (Counter = %u):\n", b + 1, current_ctr);
        printf("  Counter[%d]        : ", b); print_bits(ctr_bits, 8); printf("\n");
        printf("  E(K, Counter[%d])  : ", b); print_bits(encrypted_ctr, 8); printf("\n");
        printf("  C[%d]              : ", b); print_bits(current_c, 8); printf("\n");
        printf("  P[%d] (C XOR Enc) : ", b); print_bits(current_p, 8); printf("\n");

        current_ctr = (current_ctr + 1) % 256;
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
        printf("[SUCCESS] Recovered plaintext matches the original plaintext exactly!\n");
    } else {
        printf("[FAILED] Plaintext mismatch!\n");
    }
    printf("====================================================================\n");

    return 0;
}
