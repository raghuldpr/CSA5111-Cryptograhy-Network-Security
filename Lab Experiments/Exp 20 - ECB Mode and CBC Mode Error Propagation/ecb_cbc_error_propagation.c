#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/*
 * ============================================================================
 * Standard DES Permutation Tables and S-Boxes (FIPS PUB 46-3)
 * ============================================================================
 */

static const int IP[64] = {
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
};

static const int FP[64] = {
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41,  9, 49, 17, 57, 25
};

static const int PC1[56] = {
    57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4
};

static const int PC2[48] = {
    14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};

static const int SHIFT_SCHEDULE[16] = {
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

static const int E_TABLE[48] = {
    32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1
};

static const int P_TABLE[32] = {
    16,  7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10,
     2,  8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25
};

static const int S_BOX[8][4][16] = {
    {{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},{0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},{4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},{15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},
    {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},{3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},{0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},{13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},
    {{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},{13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},{13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},{1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},
    {{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},{13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},{10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},{3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},
    {{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},{14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},{4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},{11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},
    {{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},{10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},{9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},{4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},
    {{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},{13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},{1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},{6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},
    {{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},{1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},{7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},{2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}
};

static uint64_t permute(uint64_t input, int in_len, const int *table, int out_len) {
    uint64_t output = 0;
    for (int i = 0; i < out_len; i++) {
        int pos = table[i];
        uint64_t bit = (input >> (in_len - pos)) & 1ULL;
        output = (output << 1) | bit;
    }
    return output;
}

static void generate_subkeys(uint64_t key64, uint64_t subkeys[16]) {
    uint64_t permuted56 = permute(key64, 64, PC1, 56);
    uint32_t C = (uint32_t)((permuted56 >> 28) & 0x0FFFFFFF);
    uint32_t D = (uint32_t)(permuted56 & 0x0FFFFFFF);

    for (int r = 0; r < 16; r++) {
        int shift = SHIFT_SCHEDULE[r];
        C = ((C << shift) | (C >> (28 - shift))) & 0x0FFFFFFF;
        D = ((D << shift) | (D >> (28 - shift))) & 0x0FFFFFFF;
        uint64_t CD = (((uint64_t)C) << 28) | (uint64_t)D;
        subkeys[r] = permute(CD, 56, PC2, 48);
    }
}

static uint32_t feistel(uint32_t R, uint64_t subkey48) {
    uint64_t expanded = permute((uint64_t)R, 32, E_TABLE, 48);
    uint64_t xored = expanded ^ subkey48;
    uint32_t s_output = 0;
    for (int i = 0; i < 8; i++) {
        int shift = 42 - (i * 6);
        uint8_t chunk = (uint8_t)((xored >> shift) & 0x3F);
        int row = ((chunk & 0x20) >> 4) | (chunk & 0x01);
        int col = (chunk >> 1) & 0x0F;
        uint8_t s_val = (uint8_t)S_BOX[i][row][col];
        s_output = (s_output << 4) | s_val;
    }
    return (uint32_t)permute((uint64_t)s_output, 32, P_TABLE, 32);
}

static uint64_t des_block(uint64_t block64, const uint64_t subkeys[16], int is_decrypt) {
    uint64_t permuted = permute(block64, 64, IP, 64);
    uint32_t L = (uint32_t)((permuted >> 32) & 0xFFFFFFFF);
    uint32_t R = (uint32_t)(permuted & 0xFFFFFFFF);

    for (int i = 0; i < 16; i++) {
        int r = is_decrypt ? (15 - i) : i;
        uint32_t f_res = feistel(R, subkeys[r]);
        uint32_t new_R = L ^ f_res;
        L = R;
        R = new_R;
    }

    uint64_t pre_output = (((uint64_t)R) << 32) | (uint64_t)L;
    return permute(pre_output, 64, FP, 64);
}

static uint64_t des_encrypt(uint64_t block64, uint64_t key64) {
    uint64_t subkeys[16];
    generate_subkeys(key64, subkeys);
    return des_block(block64, subkeys, 0);
}

static uint64_t des_decrypt(uint64_t block64, uint64_t key64) {
    uint64_t subkeys[16];
    generate_subkeys(key64, subkeys);
    return des_block(block64, subkeys, 1);
}

/* Helper to convert 64-bit uint into 8-byte ASCII representation */
void to_ascii(uint64_t block, char str[9]) {
    for (int i = 0; i < 8; i++) {
        char ch = (char)((block >> (56 - (i * 8))) & 0xFF);
        str[i] = (ch >= 32 && ch <= 126) ? ch : '.';
    }
    str[8] = '\0';
}

int main(void) {
    const uint64_t key = 0x0123456789ABCDEFULL;
    const uint64_t iv  = 0xFEDCBA9876543210ULL;

    /* 3 Source Plaintext blocks */
    const uint64_t P1 = 0x41545441434B4154ULL; /* "ATTACKAT" */
    const uint64_t P2 = 0x4441574E31323334ULL; /* "DAWN1234" */
    const uint64_t P3 = 0x544F4D4F52524F57ULL; /* "TOMORROW" */

    char s1[9], s2[9], s3[9];

    printf("====================================================================\n");
    printf("   EXP 20: ECB AND CBC MODE ERROR PROPAGATION ANALYSIS\n");
    printf("====================================================================\n\n");

    to_ascii(P1, s1); to_ascii(P2, s2); to_ascii(P3, s3);
    printf("Original Source Plaintext Blocks:\n");
    printf("  P1: %016llX (\"%s\")\n", (unsigned long long)P1, s1);
    printf("  P2: %016llX (\"%s\")\n", (unsigned long long)P2, s2);
    printf("  P3: %016llX (\"%s\")\n", (unsigned long long)P3, s3);
    printf("Key:  %016llX | IV: %016llX\n\n", (unsigned long long)key, (unsigned long long)iv);

    /* ------------------------------------------------------------- */
    /* PART 1: ECB MODE ERROR PROPAGATION                            */
    /* ------------------------------------------------------------- */
    printf("--------------------------------------------------------------------\n");
    printf("1. ECB MODE: TRANSMISSION ERROR IN CIPHERTEXT BLOCK C1\n");
    printf("--------------------------------------------------------------------\n");

    /* ECB Encryption: C_i = E(P_i) */
    uint64_t ecb_C1 = des_encrypt(P1, key);
    uint64_t ecb_C2 = des_encrypt(P2, key);
    uint64_t ecb_C3 = des_encrypt(P3, key);

    /* Inject 1-bit error in C1 (flip LSB: bit 0) */
    uint64_t ecb_C1_err = ecb_C1 ^ 0x0000000000000001ULL;

    /* ECB Decryption: P_i = D(C_i) */
    uint64_t ecb_P1_dec = des_decrypt(ecb_C1_err, key);
    uint64_t ecb_P2_dec = des_decrypt(ecb_C2, key);
    uint64_t ecb_P3_dec = des_decrypt(ecb_C3, key);

    to_ascii(ecb_P1_dec, s1); to_ascii(ecb_P2_dec, s2); to_ascii(ecb_P3_dec, s3);

    printf("C1 original : %016llX -> C1 with 1-bit error: %016llX\n\n",
           (unsigned long long)ecb_C1, (unsigned long long)ecb_C1_err);
    printf("Decrypted Plaintext after C1 transmission error:\n");
    printf("  P1* = %016llX (\"%s\") -> [CORRUPTED UNPREDICTABLY]\n", (unsigned long long)ecb_P1_dec, s1);
    printf("  P2* = %016llX (\"%s\") -> [COMPLETELY UNCHANGED - NO ERROR]\n", (unsigned long long)ecb_P2_dec, s2);
    printf("  P3* = %016llX (\"%s\") -> [COMPLETELY UNCHANGED - NO ERROR]\n\n", (unsigned long long)ecb_P3_dec, s3);
    printf("ECB MODE SUMMARY:\n");
    printf("Error in C1 affects only P1.\n\n");

    /* ------------------------------------------------------------- */
    /* PART 2: CBC MODE TRANSMISSION ERROR IN CIPHERTEXT BLOCK C1    */
    /* ------------------------------------------------------------- */
    printf("--------------------------------------------------------------------\n");
    printf("2. CBC MODE: TRANSMISSION ERROR IN CIPHERTEXT BLOCK C1\n");
    printf("--------------------------------------------------------------------\n");

    /* CBC Encryption: C[i] = E(P[i] XOR C[i-1]), C[0] = IV */
    uint64_t cbc_C1 = des_encrypt(P1 ^ iv, key);
    uint64_t cbc_C2 = des_encrypt(P2 ^ cbc_C1, key);
    uint64_t cbc_C3 = des_encrypt(P3 ^ cbc_C2, key);

    /* Inject 1-bit error in transmitted C1 (flip LSB: bit 0) */
    uint64_t cbc_C1_err = cbc_C1 ^ 0x0000000000000001ULL;

    /* CBC Decryption: P[i] = D(C[i]) XOR C[i-1] */
    uint64_t cbc_P1_dec = des_decrypt(cbc_C1_err, key) ^ iv;
    uint64_t cbc_P2_dec = des_decrypt(cbc_C2, key) ^ cbc_C1_err; /* C1 modified! */
    uint64_t cbc_P3_dec = des_decrypt(cbc_C3, key) ^ cbc_C2;     /* C2 and C3 intact! */

    to_ascii(cbc_P1_dec, s1); to_ascii(cbc_P2_dec, s2); to_ascii(cbc_P3_dec, s3);

    printf("C1 original : %016llX -> Transmitted C1 with 1-bit error: %016llX\n\n",
           (unsigned long long)cbc_C1, (unsigned long long)cbc_C1_err);
    printf("Decrypted Plaintext at Receiver:\n");
    printf("  P1* = %016llX (\"%s\") -> [CORRUPTED UNPREDICTABLY]\n", (unsigned long long)cbc_P1_dec, s1);
    printf("  P2* = %016llX (\"%s\") -> [EXACT BIT 0 FLIPPED: '4'->'5']\n", (unsigned long long)cbc_P2_dec, s2);
    printf("  P3* = %016llX (\"%s\") -> [COMPLETELY UNCHANGED - NO ERROR]\n\n", (unsigned long long)cbc_P3_dec, s3);
    printf("CBC MODE SUMMARY:\n");
    printf("Error in transmitted C1 affects P1 and P2.\n");
    printf("P1 is corrupted unpredictably.\n");
    printf("The corresponding bit in P2 is flipped.\n");
    printf("P3 and subsequent blocks remain unchanged.\n\n");

    /* ------------------------------------------------------------- */
    /* PART 3: CBC MODE ERROR IN SOURCE PLAINTEXT BLOCK P1           */
    /* ------------------------------------------------------------- */
    printf("--------------------------------------------------------------------\n");
    printf("3. CBC ENCRYPTION: ERROR IN SOURCE PLAINTEXT BLOCK P1 BEFORE ENCRYPTION\n");
    printf("--------------------------------------------------------------------\n");

    /* Introduce 1-bit error in source P1 before encryption */
    uint64_t P1_modified = P1 ^ 0x0000000000000001ULL; /* 'T' -> 'U' */

    uint64_t cbc_C1_mod = des_encrypt(P1_modified ^ iv, key);
    uint64_t cbc_C2_mod = des_encrypt(P2 ^ cbc_C1_mod, key);
    uint64_t cbc_C3_mod = des_encrypt(P3 ^ cbc_C2_mod, key);

    printf("Original C1: %016llX | Modified C1: %016llX -> [DIFFERENT]\n",
           (unsigned long long)cbc_C1, (unsigned long long)cbc_C1_mod);
    printf("Original C2: %016llX | Modified C2: %016llX -> [DIFFERENT]\n",
           (unsigned long long)cbc_C2, (unsigned long long)cbc_C2_mod);
    printf("Original C3: %016llX | Modified C3: %016llX -> [DIFFERENT]\n\n",
           (unsigned long long)cbc_C3, (unsigned long long)cbc_C3_mod);

    printf("CBC ENCRYPTION SUMMARY:\n");
    printf("Error in source P1 affects C1 and all\n");
    printf("subsequent ciphertext blocks.\n\n");

    printf("====================================================================\n");
    printf("Result: ECB and CBC error propagation studied.\n");
    printf("====================================================================\n");

    return 0;
}
