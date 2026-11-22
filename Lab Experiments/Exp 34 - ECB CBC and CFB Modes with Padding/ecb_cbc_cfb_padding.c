/*
 * ============================================================================
 * Experiment 34: ECB, CBC and CFB Modes with Padding Demonstration
 *
 * Objective:
 *   Demonstrate the "1-bit followed by zero or more 0-bits" padding method
 *   for Electronic Codebook (ECB), Cipher Block Chaining (CBC), and Cipher
 *   Feedback (CFB) modes.
 *
 * Padding Scheme:
 *   1. Append a single '1' bit.
 *   2. Append zero or more '0' bits until the message length is a multiple
 *      of the block/segment size.
 *   3. If the message length is ALREADY an exact multiple of the block size,
 *      a complete dummy padding block/segment is appended.
 *
 * Motivation for Full Block Padding when Aligned:
 *   The primary motivation for appending a complete padding block even when
 *   the message is already aligned is to ELIMINATE AMBIGUITY during decryption.
 *   If padding were optional, the receiver would not know whether trailing
 *   bits like "...1000" are valid message data or padding.
 *   With unconditional padding:
 *     - The receiver scans backward from the end of the ciphertext.
 *     - Discards all trailing '0' bits.
 *     - Discards the single '1' bit immediately preceding them.
 *     - Exactly recovers the original message without ambiguity.
 *
 * NOTE: This program demonstrates padding logic, not cipher encryption.
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_BITS 2048

// Validates that string contains only '0' and '1' characters
int is_valid_binary(const char *str) {
    int len = strlen(str);
    if (len == 0) return 0;
    for (int i = 0; i < len; i++) {
        if (str[i] != '0' && str[i] != '1') {
            return 0;
        }
    }
    return 1;
}

// Pads input binary string according to the "1 followed by 0s" rule
void apply_padding(const char *input, int unit_size, char *output, int *pad_count) {
    int original_len = strlen(input);

    // Calculate padding bits needed
    int remainder = original_len % unit_size;
    // When remainder == 0, pad_bits == unit_size (complete padding block appended)
    int pad_bits = unit_size - remainder;

    // Copy original plaintext
    strcpy(output, input);

    // Append '1' bit
    output[original_len] = '1';

    // Append trailing '0' bits
    for (int i = 1; i < pad_bits; i++) {
        output[original_len + i] = '0';
    }
    output[original_len + pad_bits] = '\0';

    *pad_count = pad_bits;
}

// Displays binary string broken into blocks or segments
void print_blocks(const char *bits, int unit_size) {
    int len = strlen(bits);
    int block_num = 1;
    for (int i = 0; i < len; i += unit_size) {
        printf("    Block %2d: ", block_num++);
        for (int j = 0; j < unit_size && (i + j) < len; j++) {
            putchar(bits[i + j]);
        }
        printf("\n");
    }
}

int main(void) {
    char plaintext[MAX_BITS];
    char padded_ecb[MAX_BITS];
    char padded_cbc[MAX_BITS];
    char padded_cfb[MAX_BITS];
    int block_size;
    int cfb_segment_size;
    int pad_len_ecb, pad_len_cbc, pad_len_cfb;

    printf("====================================================================\n");
    printf("   EXPERIMENT 34: ECB, CBC AND CFB MODES WITH PADDING DEMO          \n");
    printf("   (Padding Scheme: Append '1' followed by zero or more '0's)       \n");
    printf("====================================================================\n\n");

    // 1. Accept binary plaintext
    printf("Enter binary plaintext (e.g., 1101011010): ");
    if (scanf("%1023s", plaintext) != 1) {
        printf("[ERROR] Failed to read plaintext.\n");
        return 1;
    }

    if (!is_valid_binary(plaintext)) {
        printf("[ERROR] Invalid binary string. Only '0' and '1' are allowed.\n");
        return 1;
    }

    // 2. Accept block size (ECB & CBC)
    printf("Enter block size for ECB and CBC (bits, e.g., 8): ");
    if (scanf("%d", &block_size) != 1 || block_size <= 0) {
        printf("[ERROR] Invalid block size.\n");
        return 1;
    }

    // 3. Accept CFB segment size (j bits)
    printf("Enter segment size for CFB mode (bits, e.g., 4): ");
    if (scanf("%d", &cfb_segment_size) != 1 || cfb_segment_size <= 0) {
        printf("[ERROR] Invalid CFB segment size.\n");
        return 1;
    }

    int original_len = strlen(plaintext);
    printf("\n--------------------------------------------------------------------\n");
    printf("                         INPUT SUMMARY                              \n");
    printf("--------------------------------------------------------------------\n");
    printf("Original Plaintext        : %s\n", plaintext);
    printf("Plaintext Length          : %d bits\n", original_len);
    printf("ECB/CBC Block Size        : %d bits\n", block_size);
    printf("CFB Segment Size          : %d bits\n", cfb_segment_size);

    // Apply padding for ECB and CBC (both use block_size)
    apply_padding(plaintext, block_size, padded_ecb, &pad_len_ecb);
    apply_padding(plaintext, block_size, padded_cbc, &pad_len_cbc);

    // Apply padding for CFB (uses cfb_segment_size)
    apply_padding(plaintext, cfb_segment_size, padded_cfb, &pad_len_cfb);

    // Display ECB Mode Padding
    printf("\n--------------------------------------------------------------------\n");
    printf("                     1. ECB MODE PADDING                            \n");
    printf("--------------------------------------------------------------------\n");
    printf("Unit Size                 : %d bits (Block Size)\n", block_size);
    printf("Alignment Status          : %s\n",
           (original_len % block_size == 0) ? "Aligned (Full padding block appended)" : "Unaligned (Partial padding appended)");
    printf("Padding Bits Added        : %d bits\n", pad_len_ecb);
    printf("Padded Binary String      : %s\n", padded_ecb);
    printf("Total Padded Length       : %d bits (%d blocks)\n",
           (int)strlen(padded_ecb), (int)strlen(padded_ecb) / block_size);
    printf("Block Breakdown:\n");
    print_blocks(padded_ecb, block_size);

    // Display CBC Mode Padding
    printf("\n--------------------------------------------------------------------\n");
    printf("                     2. CBC MODE PADDING                            \n");
    printf("--------------------------------------------------------------------\n");
    printf("Unit Size                 : %d bits (Block Size)\n", block_size);
    printf("Alignment Status          : %s\n",
           (original_len % block_size == 0) ? "Aligned (Full padding block appended)" : "Unaligned (Partial padding appended)");
    printf("Padding Bits Added        : %d bits\n", pad_len_cbc);
    printf("Padded Binary String      : %s\n", padded_cbc);
    printf("Total Padded Length       : %d bits (%d blocks)\n",
           (int)strlen(padded_cbc), (int)strlen(padded_cbc) / block_size);
    printf("Block Breakdown:\n");
    print_blocks(padded_cbc, block_size);

    // Display CFB Mode Padding
    printf("\n--------------------------------------------------------------------\n");
    printf("                     3. CFB MODE PADDING                            \n");
    printf("--------------------------------------------------------------------\n");
    printf("Unit Size                 : %d bits (CFB Segment Size)\n", cfb_segment_size);
    printf("Alignment Status          : %s\n",
           (original_len % cfb_segment_size == 0) ? "Aligned (Full padding segment appended)" : "Unaligned (Partial padding appended)");
    printf("Padding Bits Added        : %d bits\n", pad_len_cfb);
    printf("Padded Binary String      : %s\n", padded_cfb);
    printf("Total Padded Length       : %d bits (%d segments)\n",
           (int)strlen(padded_cfb), (int)strlen(padded_cfb) / cfb_segment_size);
    printf("Segment Breakdown:\n");
    print_blocks(padded_cfb, cfb_segment_size);

    // Theoretical Explanation of Full Block Padding
    printf("\n====================================================================\n");
    printf("         MOTIVATION FOR FULL-BLOCK PADDING WHEN ALIGNED             \n");
    printf("====================================================================\n");
    printf("Question: Why append a complete padding block even when aligned?\n");
    printf("Answer  : To make unpadding 100%% unambiguous.\n\n");
    printf("Explanation:\n");
    printf("  1. If padding were skipped on aligned messages, the receiver could\n");
    printf("     not determine whether a message ending in '1000' had genuine\n");
    printf("     payload bits '1000' or 4 bits of padding.\n");
    printf("  2. By ALWAYS appending '1' followed by '0's (even if it requires a\n");
    printf("     full dummy block), the receiver ALWAYS reliably strips trailing\n");
    printf("     '0' bits and the preceding '1' bit without any ambiguity.\n");
    printf("====================================================================\n");
    printf("[SUCCESS] Padding demonstration completed successfully.\n");

    return 0;
}
