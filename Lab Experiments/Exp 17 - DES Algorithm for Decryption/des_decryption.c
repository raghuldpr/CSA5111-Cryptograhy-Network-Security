#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

/*
 * ============================================================================
 * Standard DES Permutation Tables and S-Boxes (FIPS PUB 46-3)
 * ============================================================================
 */

/* Initial Permutation (IP): 64 bits -> 64 bits */
static const int IP[64] = {
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
};

/* Final Permutation (FP / IP^-1): 64 bits -> 64 bits */
static const int FP[64] = {
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41,  9, 49, 17, 57, 25
};

/* Permuted Choice 1 (PC-1): 64-bit key -> 56 bits (ignoring parity bits) */
static const int PC1[56] = {
    57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4
};

/* Permuted Choice 2 (PC-2): 56 bits -> 48-bit round subkey */
static const int PC2[48] = {
    14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};

/* Left Shift Schedule for the 16 rounds */
static const int SHIFT_SCHEDULE[16] = {
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

/* Expansion Permutation (E): 32 bits -> 48 bits */
static const int E_TABLE[48] = {
    32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1
};

/* P-Box Permutation: 32 bits -> 32 bits */
static const int P_TABLE[32] = {
    16,  7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10,
     2,  8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25
};

/* 8 Standard DES Substitution Boxes (S1 to S8) */
static const int S_BOX[8][4][16] = {
    /* S1 */
    {
        {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
        { 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
        { 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
        {15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13}
    },
    /* S2 */
    {
        {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
        { 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
        { 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
        {13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9}
    },
    /* S3 */
    {
        {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
        {13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
        {13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
        { 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12}
    },
    /* S4 */
    {
        { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
        {13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
        {10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
        { 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14}
    },
    /* S5 */
    {
        { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
        {14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
        { 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
        {11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3}
    },
    /* S6 */
    {
        {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
        {10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
        { 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
        { 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13}
    },
    /* S7 */
    {
        { 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1},
        {13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
        { 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
        { 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12}
    },
    /* S8 */
    {
        {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7},
        { 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2},
        { 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
        { 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11}
    }
};

/* Permute input bits using a table */
uint64_t permute(uint64_t input, int in_len, const int *table, int out_len) {
    uint64_t output = 0;
    for (int i = 0; i < out_len; i++) {
        int pos = table[i];
        uint64_t bit = (input >> (in_len - pos)) & 1ULL;
        output = (output << 1) | bit;
    }
    return output;
}

/* Generate all 16 48-bit subkeys from a 64-bit key */
void generate_subkeys(uint64_t key64, uint64_t subkeys[16]) {
    /* PC-1 produces 56 bits */
    uint64_t permuted56 = permute(key64, 64, PC1, 56);
    uint32_t C = (uint32_t)((permuted56 >> 28) & 0x0FFFFFFF);
    uint32_t D = (uint32_t)(permuted56 & 0x0FFFFFFF);

    for (int r = 0; r < 16; r++) {
        int shift = SHIFT_SCHEDULE[r];
        /* 28-bit circular left shift */
        C = ((C << shift) | (C >> (28 - shift))) & 0x0FFFFFFF;
        D = ((D << shift) | (D >> (28 - shift))) & 0x0FFFFFFF;

        uint64_t CD = (((uint64_t)C) << 28) | (uint64_t)D;
        subkeys[r] = permute(CD, 56, PC2, 48);
    }
}

/* Feistel function F(R, K) */
uint32_t feistel(uint32_t R, uint64_t subkey48) {
    /* 1. Expansion permutation: 32 bits -> 48 bits */
    uint64_t expanded = permute((uint64_t)R, 32, E_TABLE, 48);

    /* 2. Key XOR */
    uint64_t xored = expanded ^ subkey48;

    /* 3. S-Box substitution: 48 bits -> 32 bits */
    uint32_t s_output = 0;
    for (int i = 0; i < 8; i++) {
        /* Extract 6-bit chunk from MSB to LSB */
        int shift = 42 - (i * 6);
        uint8_t chunk = (uint8_t)((xored >> shift) & 0x3F);

        int row = ((chunk & 0x20) >> 4) | (chunk & 0x01);
        int col = (chunk >> 1) & 0x0F;

        uint8_t s_val = (uint8_t)S_BOX[i][row][col];
        s_output = (s_output << 4) | s_val;
    }

    /* 4. P-Box permutation: 32 bits -> 32 bits */
    return (uint32_t)permute((uint64_t)s_output, 32, P_TABLE, 32);
}

/* DES Decryption: apply subkeys in reverse order (K16 down to K1) */
uint64_t des_decrypt(uint64_t ciphertext, const uint64_t subkeys[16]) {
    /* 1. Initial Permutation (IP) */
    uint64_t permuted = permute(ciphertext, 64, IP, 64);
    uint32_t L = (uint32_t)((permuted >> 32) & 0xFFFFFFFF);
    uint32_t R = (uint32_t)(permuted & 0xFFFFFFFF);

    /* 2. 16 Feistel rounds with reverse key schedule (K16 -> K1) */
    for (int r = 15; r >= 0; r--) {
        uint32_t f_res = feistel(R, subkeys[r]);
        uint32_t new_R = L ^ f_res;
        L = R;
        R = new_R;
    }

    /* 3. Pre-output swap (R16 || L16) */
    uint64_t pre_output = (((uint64_t)R) << 32) | (uint64_t)L;

    /* 4. Final Permutation (FP / IP^-1) */
    return permute(pre_output, 64, FP, 64);
}

int main(void) {
    char key_str[64];
    char ct_str[64];
    uint64_t key64 = 0x133457799BBCDFF1ULL;
    uint64_t ct64  = 0x85E813540F0AB405ULL;
    uint64_t subkeys[16];

    printf("====================================================================\n");
    printf("   EXP 17: DES ALGORITHM FOR DECRYPTION (MANUAL IMPLEMENTATION)\n");
    printf("====================================================================\n\n");

    printf("Enter 64-bit Hexadecimal Key (press ENTER for test vector: 133457799BBCDFF1):\n> ");
    if (fgets(key_str, sizeof(key_str), stdin) != NULL) {
        key_str[strcspn(key_str, "\r\n")] = '\0';
        if (strlen(key_str) >= 16) {
            key64 = strtoull(key_str, NULL, 16);
        }
    }

    printf("Enter 64-bit Hexadecimal Ciphertext (press ENTER for test vector: 85E813540F0AB405):\n> ");
    if (fgets(ct_str, sizeof(ct_str), stdin) != NULL) {
        ct_str[strcspn(ct_str, "\r\n")] = '\0';
        if (strlen(ct_str) >= 16) {
            ct64 = strtoull(ct_str, NULL, 16);
        }
    }

    printf("\n[Active Input Parameters]:\n");
    printf("  Key (64-bit Hex)       : %016llX\n", (unsigned long long)key64);
    printf("  Ciphertext (64-bit Hex): %016llX\n", (unsigned long long)ct64);

    /* Generate all 16 subkeys */
    generate_subkeys(key64, subkeys);

    printf("\n--------------------------------------------------------------------\n");
    printf("1. REVERSE ROUND-KEY SCHEDULE FOR DECRYPTION\n");
    printf("--------------------------------------------------------------------\n");
    printf("Decryption Feistel rounds use subkeys in reverse order: K16 -> K1\n\n");
    for (int r = 15; r >= 0; r--) {
        printf("Round %2d uses K%-2d: %012llX  ", 16 - r, r + 1, (unsigned long long)subkeys[r]);
        if ((16 - r) % 2 == 0) printf("\n");
    }

    /* Perform DES Decryption */
    uint64_t plaintext = des_decrypt(ct64, subkeys);

    printf("\n--------------------------------------------------------------------\n");
    printf("2. DECRYPTION RESULTS & VERIFICATION\n");
    printf("--------------------------------------------------------------------\n");
    printf("Decrypted Plaintext (Hex) : %016llX\n", (unsigned long long)plaintext);
    printf("Expected Plaintext (Hex)  : 0123456789ABCDEF\n");

    if (plaintext == 0x0123456789ABCDEFULL) {
        printf("Verification Status       : SUCCESS (Exact match with NIST/NBS test vector)\n");
    } else {
        printf("Verification Status       : CUSTOM INPUT PROCESSED\n");
    }

    printf("\n--------------------------------------------------------------------\n");
    printf("3. ALGORITHM ARCHITECTURE EXPLANATION\n");
    printf("--------------------------------------------------------------------\n");
    printf("- Initial Permutation (IP) rearranges the 64 input ciphertext bits.\n");
    printf("- 16 Feistel Rounds execute: L[i] = R[i-1], R[i] = L[i-1] XOR F(R[i-1], K[17-i]).\n");
    printf("- F function: 32-bit R expands to 48 bits (E), XORed with 48-bit subkey,\n");
    printf("  substituted through 8 non-linear S-boxes (48->32 bits), and permuted (P-box).\n");
    printf("- Final Permutation (FP = IP^-1) produces the recovered 64-bit plaintext.\n");
    printf("====================================================================\n");

    return 0;
}
