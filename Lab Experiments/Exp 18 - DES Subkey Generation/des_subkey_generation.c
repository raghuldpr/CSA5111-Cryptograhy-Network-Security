#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

/*
 * ============================================================================
 * Standard DES Key-Schedule Permutation Tables (FIPS PUB 46-3)
 * ============================================================================
 */

/* Permuted Choice 1 (PC-1): 64-bit key -> 56 bits (ignoring parity bits 8, 16, 24, 32, 40, 48, 56, 64) */
static const int PC1[56] = {
    57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4
};

/* Permuted Choice 2 (PC-2): 56 bits (C || D) -> 48-bit round key */
/* Note: First 24 positions are chosen exclusively from C (values <= 28) */
/*       Second 24 positions are chosen exclusively from D (values >= 29) */
static const int PC2[48] = {
    14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};

/* Left-shift schedule for the 16 rounds (rounds 1, 2, 9, 16 rotate by 1; others by 2) */
static const int SHIFT_SCHEDULE[16] = {
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
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

int main(void) {
    char key_str[64];
    uint64_t key64 = 0x133457799BBCDFF1ULL;
    uint64_t subkeys[16];

    printf("====================================================================\n");
    printf("   EXP 18: DES SUBKEY GENERATION (KEY SCHEDULE ALGORITHM)\n");
    printf("====================================================================\n\n");

    printf("Enter 64-bit Hexadecimal Key (press ENTER for test vector: 133457799BBCDFF1):\n> ");
    if (fgets(key_str, sizeof(key_str), stdin) != NULL) {
        key_str[strcspn(key_str, "\r\n")] = '\0';
        if (strlen(key_str) >= 16) {
            key64 = strtoull(key_str, NULL, 16);
        }
    }

    printf("\n[Initial Master Key]: %016llX\n\n", (unsigned long long)key64);

    /* Step 1: Apply PC-1 to obtain 56 effective key bits */
    uint64_t permuted56 = permute(key64, 64, PC1, 56);
    uint32_t C = (uint32_t)((permuted56 >> 28) & 0x0FFFFFFF);
    uint32_t D = (uint32_t)(permuted56 & 0x0FFFFFFF);

    printf("--------------------------------------------------------------------\n");
    printf("1. PERMUTED CHOICE 1 (PC-1) RESULT & INITIAL 28-BIT HALVES\n");
    printf("--------------------------------------------------------------------\n");
    printf("56-bit Key after PC-1 : %014llX\n", (unsigned long long)permuted56);
    printf("Initial C0 (28 bits)  : %07X\n", C);
    printf("Initial D0 (28 bits)  : %07X\n\n", D);

    /* Step 2: 16 Rounds of Left Shifts and PC-2 Permutation */
    printf("--------------------------------------------------------------------\n");
    printf("2. ROUND-BY-ROUND ROTATION & 48-BIT SUBKEY GENERATION (PC-2)\n");
    printf("--------------------------------------------------------------------\n");
    printf("%-5s | %-5s | %-7s | %-7s | %-12s | %s\n",
           "Round", "Shift", "C[i]", "D[i]", "Subkey (Hex)", "First 24b (C) | Second 24b (D)");
    printf("------+-------+---------+---------+--------------+-------------------------\n");

    for (int r = 0; r < 16; r++) {
        int shift = SHIFT_SCHEDULE[r];

        /* Circular left shift on 28-bit halves */
        C = ((C << shift) | (C >> (28 - shift))) & 0x0FFFFFFF;
        D = ((D << shift) | (D >> (28 - shift))) & 0x0FFFFFFF;

        /* Combine C and D into 56 bits */
        uint64_t CD = (((uint64_t)C) << 28) | (uint64_t)D;

        /* Apply PC-2 to produce 48-bit subkey */
        subkeys[r] = permute(CD, 56, PC2, 48);

        uint32_t subkey_c_part = (uint32_t)((subkeys[r] >> 24) & 0xFFFFFF);
        uint32_t subkey_d_part = (uint32_t)(subkeys[r] & 0xFFFFFF);

        printf("K%-4d |  %-4d | %07X | %07X | %012llX | %06X      | %06X\n",
               r + 1, shift, C, D, (unsigned long long)subkeys[r],
               subkey_c_part, subkey_d_part);
    }

    /* Verification of key test vectors */
    printf("\n--------------------------------------------------------------------\n");
    printf("3. TEST VECTOR VERIFICATION (Sample Rounds K1, K2, K3, K4, K16)\n");
    printf("--------------------------------------------------------------------\n");
    printf("Subkey K1  : %012llX (Expected: 1B02EFFC7072) -> %s\n",
           (unsigned long long)subkeys[0],
           (subkeys[0] == 0x1B02EFFC7072ULL) ? "MATCH" : "CUSTOM");
    printf("Subkey K2  : %012llX (Expected: 79AED9DBC9E5) -> %s\n",
           (unsigned long long)subkeys[1],
           (subkeys[1] == 0x79AED9DBC9E5ULL) ? "MATCH" : "CUSTOM");
    printf("Subkey K3  : %012llX (Expected: 55FC8A42CF99) -> %s\n",
           (unsigned long long)subkeys[2],
           (subkeys[2] == 0x55FC8A42CF99ULL) ? "MATCH" : "CUSTOM");
    printf("Subkey K4  : %012llX (Expected: 72ADD6DB351D) -> %s\n",
           (unsigned long long)subkeys[3],
           (subkeys[3] == 0x72ADD6DB351DULL) ? "MATCH" : "CUSTOM");
    printf("Subkey K16 : %012llX (Expected: CB3D8B0E17F5) -> %s\n",
           (unsigned long long)subkeys[15],
           (subkeys[15] == 0xCB3D8B0E17F5ULL) ? "MATCH" : "CUSTOM");

    printf("\n--------------------------------------------------------------------\n");
    printf("4. KEY PROPERTY DEMONSTRATION (PC-2 DISJOINT SUBSET PROPERTY)\n");
    printf("--------------------------------------------------------------------\n");
    printf("Stallings Key Schedule Analysis:\n");
    printf("1. Permuted Choice 2 (PC-2) table has entries 1..24 all <= 28.\n");
    printf("   Therefore, the first 24 bits of each subkey come strictly from C.\n");
    printf("2. PC-2 table entries 25..48 are all >= 29.\n");
    printf("   Therefore, the second 24 bits of each subkey come strictly from D.\n");
    printf("3. C and D remain disjoint 28-bit sets throughout all 16 rounds.\n");
    printf("   No bit from C ever influences the second 24 bits of a subkey,\n");
    printf("   and no bit from D ever influences the first 24 bits of a subkey.\n");
    printf("====================================================================\n");

    return 0;
}
