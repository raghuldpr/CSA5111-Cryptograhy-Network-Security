/*
 * ============================================================================
 * Experiment 31: CMAC Subkey Generation (NIST SP 800-38B)
 *
 * Objective:
 *   Demonstrate the generation of subkeys K1 and K2 for Cipher-based Message
 *   Authentication Code (CMAC) using block cipher output L = E(K, 0^b).
 *
 * Mathematical Background:
 *   CMAC generates two subkeys, K1 and K2, derived from L = CIPH_K(0^b)
 *   through multiplication by x (equivalent to a 1-bit left shift) in the
 *   finite field GF(2^b), where b is the block length (64 or 128 bits).
 *
 * Subkey Generation Logic:
 *   Let MSB(X) be the most significant bit of block X.
 *
 *   1. Subkey K1:
 *      - If MSB(L) == 0:
 *          K1 = L << 1
 *      - If MSB(L) == 1:
 *          K1 = (L << 1) XOR Rb
 *
 *   2. Subkey K2:
 *      - If MSB(K1) == 0:
 *          K2 = K1 << 1
 *      - If MSB(K1) == 1:
 *          K2 = (K1 << 1) XOR Rb
 *
 * Reduction Constants (Rb):
 *   - For 64-bit block (e.g., 3DES):
 *       Rb = 0x1B (irreducible polynomial x^64 + x^4 + x^3 + x + 1)
 *   - For 128-bit block (e.g., AES):
 *       Rb = 0x87 (irreducible polynomial x^128 + x^7 + x^2 + x + 1)
 *
 * Note on Shift Operation:
 *   The shift is executed over an array of bytes from right to left so that
 *   carry bits properly propagate across the full 64-bit or 128-bit block.
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_BLOCK_BYTES 16 // Up to 128 bits (16 bytes)

// Converts a hex character to its 4-bit integer value
int hex_char_to_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Converts a hex string into an array of bytes
int hex_to_bytes(const char *hex_str, unsigned char *bytes, int expected_bytes) {
    int len = strlen(hex_str);
    if (len != expected_bytes * 2) {
        return 0; // Length mismatch
    }
    for (int i = 0; i < expected_bytes; i++) {
        int hi = hex_char_to_val(hex_str[2 * i]);
        int lo = hex_char_to_val(hex_str[2 * i + 1]);
        if (hi < 0 || lo < 0) return 0;
        bytes[i] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}

// Prints a byte array in hexadecimal format
void print_hex_block(const char *label, const unsigned char *bytes, int num_bytes) {
    printf("%-20s: ", label);
    for (int i = 0; i < num_bytes; i++) {
        printf("%02X", bytes[i]);
    }
    printf("\n");
}

/*
 * Generates the next CMAC subkey from the parent block.
 * Parameters:
 *   input       - Pointer to parent block bytes (L or K1)
 *   output      - Pointer to store generated subkey (K1 or K2)
 *   num_bytes   - Number of bytes (8 for 64-bit, 16 for 128-bit)
 *   rb_constant - Reduction constant (0x1B for 64-bit, 0x87 for 128-bit)
 *   msb_flag    - Output pointer to store whether MSB was 1
 */
void generate_cmac_subkey(const unsigned char *input, unsigned char *output,
                          int num_bytes, unsigned char rb_constant, int *msb_flag) {
    // 1. Detect if the Most Significant Bit (bit 7 of byte 0) is set
    *msb_flag = (input[0] & 0x80) ? 1 : 0;

    // 2. Perform 1-bit left shift on the entire multi-byte block
    // Shift from least significant byte (num_bytes - 1) to most significant byte (0)
    int carry = 0;
    for (int i = num_bytes - 1; i >= 0; i--) {
        int next_carry = (input[i] & 0x80) ? 1 : 0;
        output[i] = (unsigned char)(((input[i] << 1) & 0xFF) | carry);
        carry = next_carry;
    }

    // 3. If MSB was 1, perform modular reduction by XORing Rb with the least significant byte
    if (*msb_flag) {
        output[num_bytes - 1] ^= rb_constant;
    }
}

int main(void) {
    int block_bits;
    int num_bytes;
    unsigned char rb_constant;
    char hex_input[128];
    unsigned char L[MAX_BLOCK_BYTES];
    unsigned char K1[MAX_BLOCK_BYTES];
    unsigned char K2[MAX_BLOCK_BYTES];
    int msb1, msb2;

    printf("====================================================================\n");
    printf("        EXPERIMENT 31: CMAC SUBKEY GENERATION (NIST SP 800-38B)     \n");
    printf("====================================================================\n\n");

    // 1. Block size selection
    printf("Select block size (64 or 128 bits): ");
    if (scanf("%d", &block_bits) != 1 || (block_bits != 64 && block_bits != 128)) {
        printf("[ERROR] Invalid block size. Must be 64 or 128 bits.\n");
        return 1;
    }

    if (block_bits == 64) {
        num_bytes = 8;
        rb_constant = 0x1B;
        printf("[*] Block size: 64 bits (8 bytes), Reduction constant Rb = 0x1B\n");
    } else {
        num_bytes = 16;
        rb_constant = 0x87;
        printf("[*] Block size: 128 bits (16 bytes), Reduction constant Rb = 0x87\n");
    }

    // 2. Input block cipher output L = CIPH_K(0^b)
    printf("Enter cipher output L = E(K, 0^b) as hex (%d hex characters):\n> ", num_bytes * 2);
    if (scanf("%127s", hex_input) != 1) {
        printf("[ERROR] Failed to read input.\n");
        return 1;
    }

    if (!hex_to_bytes(hex_input, L, num_bytes)) {
        printf("[ERROR] Invalid hex string. Expected exactly %d hex digits (0-9, A-F).\n", num_bytes * 2);
        return 1;
    }

    printf("\n--------------------------------------------------------------------\n");
    printf("                 STEP-BY-STEP SUBKEY COMPUTATION                    \n");
    printf("--------------------------------------------------------------------\n");
    print_hex_block("Input block (L)", L, num_bytes);

    // 3. Generate Subkey K1
    generate_cmac_subkey(L, K1, num_bytes, rb_constant, &msb1);
    printf("\n[*] Generating Subkey K1 from L:\n");
    printf("    MSB(L) = %d\n", msb1);
    if (msb1 == 0) {
        printf("    Since MSB(L) == 0: K1 = L << 1 (No reduction needed)\n");
    } else {
        printf("    Since MSB(L) == 1: K1 = (L << 1) XOR Rb (0x%02X reduction applied)\n", rb_constant);
    }
    print_hex_block("Subkey K1", K1, num_bytes);

    // 4. Generate Subkey K2
    generate_cmac_subkey(K1, K2, num_bytes, rb_constant, &msb2);
    printf("\n[*] Generating Subkey K2 from K1:\n");
    printf("    MSB(K1) = %d\n", msb2);
    if (msb2 == 0) {
        printf("    Since MSB(K1) == 0: K2 = K1 << 1 (No reduction needed)\n");
    } else {
        printf("    Since MSB(K1) == 1: K2 = (K1 << 1) XOR Rb (0x%02X reduction applied)\n", rb_constant);
    }
    print_hex_block("Subkey K2", K2, num_bytes);

    printf("\n====================================================================\n");
    printf("                        FINAL CMAC SUBKEYS                          \n");
    printf("====================================================================\n");
    print_hex_block("L  = E(K, 0^b)", L, num_bytes);
    print_hex_block("K1 (Subkey 1)", K1, num_bytes);
    print_hex_block("K2 (Subkey 2)", K2, num_bytes);
    printf("====================================================================\n");
    printf("[SUCCESS] CMAC subkeys generated successfully.\n");

    return 0;
}
