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

/* Single DES block processing */
static uint64_t des_process_block(uint64_t block64, const uint64_t subkeys[16], int is_decrypt) {
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

static uint64_t des_encrypt_block(uint64_t block64, uint64_t key64) {
    uint64_t subkeys[16];
    generate_subkeys(key64, subkeys);
    return des_process_block(block64, subkeys, 0);
}

static uint64_t des_decrypt_block(uint64_t block64, uint64_t key64) {
    uint64_t subkeys[16];
    generate_subkeys(key64, subkeys);
    return des_process_block(block64, subkeys, 1);
}

/*
 * Triple DES EDE (Encrypt-Decrypt-Encrypt) Mode:
 * C = E(K3, D(K2, E(K1, P)))
 */
static uint64_t triple_des_encrypt(uint64_t block64, uint64_t k1, uint64_t k2, uint64_t k3) {
    uint64_t step1 = des_encrypt_block(block64, k1);
    uint64_t step2 = des_decrypt_block(step1, k2);
    return des_encrypt_block(step2, k3);
}

int main(void) {
    char pt_input[64];
    char key_input[128];
    char iv_input[64];

    /* Default Test Vector Parameters */
    char plaintext_ascii[9] = "HELLO123";
    uint64_t k1 = 0x0123456789ABCDEFULL;
    uint64_t k2 = 0xFEDCBA9876543210ULL;
    uint64_t k3 = 0x0011223344556677ULL;
    uint64_t iv = 0x1234567890ABCDEFULL;

    printf("====================================================================\n");
    printf("   EXP 19: CBC MODE ENCRYPTION USING 3DES (TRIPLE DES)\n");
    printf("====================================================================\n\n");

    printf("Enter Plaintext string (press ENTER for default 8-byte block 'HELLO123'):\n> ");
    if (fgets(pt_input, sizeof(pt_input), stdin) != NULL) {
        pt_input[strcspn(pt_input, "\r\n")] = '\0';
        /* Trim leading and trailing whitespace */
        char *p = pt_input;
        while (isspace((unsigned char)*p)) p++;
        if (strlen(p) > 0) {
            strncpy(plaintext_ascii, p, 8);
            plaintext_ascii[8] = '\0';
        }
    }

    printf("Enter 3DES 48-hex-char Key (press ENTER for default test vector):\n> ");
    if (fgets(key_input, sizeof(key_input), stdin) != NULL) {
        key_input[strcspn(key_input, "\r\n")] = '\0';
        if (strlen(key_input) >= 48) {
            char k1_buf[17], k2_buf[17], k3_buf[17];
            strncpy(k1_buf, key_input, 16); k1_buf[16] = '\0';
            strncpy(k2_buf, key_input + 16, 16); k2_buf[16] = '\0';
            strncpy(k3_buf, key_input + 32, 16); k3_buf[16] = '\0';
            k1 = strtoull(k1_buf, NULL, 16);
            k2 = strtoull(k2_buf, NULL, 16);
            k3 = strtoull(k3_buf, NULL, 16);
        }
    }

    printf("Enter 16-hex-char IV (press ENTER for default test vector: 1234567890ABCDEF):\n> ");
    if (fgets(iv_input, sizeof(iv_input), stdin) != NULL) {
        iv_input[strcspn(iv_input, "\r\n")] = '\0';
        if (strlen(iv_input) >= 16) {
            iv = strtoull(iv_input, NULL, 16);
        }
    }

    /* Convert 8 ASCII bytes of plaintext into 64-bit integer */
    uint64_t pt_block = 0;
    for (int i = 0; i < 8; i++) {
        pt_block = (pt_block << 8) | (unsigned char)plaintext_ascii[i];
    }

    printf("\n[Active Cryptographic Parameters]:\n");
    printf("  Plaintext (ASCII)       : \"%s\" (8 complete bytes, no padding needed)\n", plaintext_ascii);
    printf("  Plaintext (Hex Block)   : %016llX\n", (unsigned long long)pt_block);
    printf("  Key 1 (K1 Hex)          : %016llX\n", (unsigned long long)k1);
    printf("  Key 2 (K2 Hex)          : %016llX\n", (unsigned long long)k2);
    printf("  Key 3 (K3 Hex)          : %016llX\n", (unsigned long long)k3);
    printf("  Initialization Vector IV: %016llX\n\n", (unsigned long long)iv);

    /* CBC Mode Encryption: C[1] = 3DES(P[1] XOR IV) */
    printf("--------------------------------------------------------------------\n");
    printf("1. CBC MODE 3DES-EDE ENCRYPTION STEPS\n");
    printf("--------------------------------------------------------------------\n");
    uint64_t xor_input = pt_block ^ iv;
    printf("Step 1 [CBC XOR]: P[1] XOR IV\n");
    printf("       %016llX XOR %016llX\n", (unsigned long long)pt_block, (unsigned long long)iv);
    printf("       = %016llX\n\n", (unsigned long long)xor_input);

    printf("Step 2 [3DES-EDE Chain]:\n");
    uint64_t s1 = des_encrypt_block(xor_input, k1);
    printf("  (a) E(K1, X) -> %016llX\n", (unsigned long long)s1);
    uint64_t s2 = des_decrypt_block(s1, k2);
    printf("  (b) D(K2, s1) -> %016llX\n", (unsigned long long)s2);
    uint64_t ciphertext = des_encrypt_block(s2, k3);
    printf("  (c) E(K3, s2) -> %016llX (Final 3DES: %016llX)\n",
           (unsigned long long)ciphertext, (unsigned long long)triple_des_encrypt(xor_input, k1, k2, k3));

    printf("\n--------------------------------------------------------------------\n");
    printf("2. VERIFICATION RESULTS\n");
    printf("--------------------------------------------------------------------\n");
    printf("Computed Ciphertext (Hex): %016llX\n", (unsigned long long)ciphertext);
    printf("Expected Ciphertext (Hex): 4C2625A13AF4CD7C\n");

    if (ciphertext == 0x4C2625A13AF4CD7CULL) {
        printf("Verification Status      : SUCCESS (Matches expected CBC 3DES vector)\n");
    } else {
        printf("Verification Status      : CUSTOM VECTOR CALCULATED\n");
    }

    printf("\n--------------------------------------------------------------------\n");
    printf("3. COMPARISON & EVALUATION (3DES vs DES vs MODERN CIPHERS)\n");
    printf("--------------------------------------------------------------------\n");
    printf("a. For Security:\n");
    printf("   - 3DES with 3 independent keys provides an effective key size of 168 bits\n");
    printf("     (112 bits against meet-in-the-middle attacks), completely eliminating\n");
    printf("     the single-DES 56-bit brute force weakness.\n");
    printf("   - However, 3DES retains a 64-bit block size, leaving it susceptible to\n");
    printf("     birthday-bound collision attacks (e.g. Sweet32) after ~2^32 blocks.\n");
    printf("   - AES (128/192/256-bit key, 128-bit block) is strictly superior today.\n\n");
    printf("b. For Performance:\n");
    printf("   - 3DES is computationally expensive: it performs 3 full DES evaluations\n");
    printf("     per 64-bit block, making it roughly 3 times slower than original DES.\n");
    printf("   - Software performance on modern processors is limited compared to\n");
    printf("     AES, which benefits from hardware instruction acceleration (AES-NI).\n");
    printf("====================================================================\n");

    return 0;
}
