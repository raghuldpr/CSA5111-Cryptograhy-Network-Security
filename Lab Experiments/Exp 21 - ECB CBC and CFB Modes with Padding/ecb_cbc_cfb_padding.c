/*
 * ============================================================================
 * Experiment 21: ECB, CBC and CFB Modes with Padding Demonstration
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
 * Ambiguity Prevention:
 *   Adding a full block when already aligned ensures unambiguous unpadding.
 *   The receiver always scans backward from the end, discards trailing '0's,
 *   and discards the first '1' encountered, restoring the exact plaintext.
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
    int pad_bits = unit_size - remainder; // When remainder == 0, pad_bits == unit_size (full block)
    
    // Copy original plaintext
    strcpy(output, input);
    
    // Append '1' bit
    output[original_len] = '1';
    
    // Append '0' bits
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
    printf("   EXP 21: ECB, CBC AND CFB MODES WITH PADDING DEMONSTRATION       \n");
    printf("   (Padding Scheme: Append '1' followed by zero or more '0's)       \n");
    printf("====================================================================\n\n");

    // 1. Accept binary plaintext
    printf("Enter binary plaintext (e.g., 1101011010): ");
    if (scanf("%1023s", plaintext) != 1) {
        printf("Error: Failed to read plaintext.\n");
        return 1;
    }

    if (!is_valid_binary(plaintext)) {
        printf("Error: Plaintext must contain only binary digits ('0' and '1').\n");
        return 1;
    }

    // 2. Accept block size and CFB segment size
    printf("Enter block size in bits for ECB/CBC (e.g., 8): ");
    if (scanf("%d", &block_size) != 1 || block_size <= 0) {
        printf("Error: Invalid block size.\n");
        return 1;
    }

    printf("Enter CFB segment size in bits (e.g., 4): ");
    if (scanf("%d", &cfb_segment_size) != 1 || cfb_segment_size <= 0) {
        printf("Error: Invalid CFB segment size.\n");
        return 1;
    }

    int pt_len = strlen(plaintext);
    printf("\n--------------------------------------------------------------------\n");
    printf("PLAINTEXT SUMMARY:\n");
    printf("--------------------------------------------------------------------\n");
    printf("Original Plaintext        : %s\n", plaintext);
    printf("Plaintext Length          : %d bits\n", pt_len);
    printf("ECB/CBC Block Size        : %d bits\n", block_size);
    printf("CFB Segment Size          : %d bits\n", cfb_segment_size);

    // 3. Demonstrate ECB Padding
    apply_padding(plaintext, block_size, padded_ecb, &pad_len_ecb);
    printf("\n--------------------------------------------------------------------\n");
    printf("1. ELECTRONIC CODEBOOK (ECB) MODE PADDING\n");
    printf("--------------------------------------------------------------------\n");
    printf("Block Size               : %d bits\n", block_size);
    printf("Alignment Status         : %s\n", 
           (pt_len % block_size == 0) ? "ALIGNED (Full padding block appended)" : "UNALIGNED");
    printf("Padding Bits Added       : %d bit(s) [1 followed by %d zero(es)]\n", 
           pad_len_ecb, pad_len_ecb - 1);
    printf("Padded Bitstream         : %s\n", padded_ecb);
    printf("Total Padded Length      : %lu bits (%lu blocks)\n", 
           strlen(padded_ecb), strlen(padded_ecb) / block_size);
    printf("Partitioned Blocks:\n");
    print_blocks(padded_ecb, block_size);

    // 4. Demonstrate CBC Padding
    apply_padding(plaintext, block_size, padded_cbc, &pad_len_cbc);
    printf("\n--------------------------------------------------------------------\n");
    printf("2. CIPHER BLOCK CHAINING (CBC) MODE PADDING\n");
    printf("--------------------------------------------------------------------\n");
    printf("Block Size               : %d bits\n", block_size);
    printf("Alignment Status         : %s\n", 
           (pt_len % block_size == 0) ? "ALIGNED (Full padding block appended)" : "UNALIGNED");
    printf("Padding Bits Added       : %d bit(s) [1 followed by %d zero(es)]\n", 
           pad_len_cbc, pad_len_cbc - 1);
    printf("Padded Bitstream         : %s\n", padded_cbc);
    printf("Total Padded Length      : %lu bits (%lu blocks)\n", 
           strlen(padded_cbc), strlen(padded_cbc) / block_size);
    printf("Partitioned Blocks:\n");
    print_blocks(padded_cbc, block_size);

    // 5. Demonstrate CFB Padding
    apply_padding(plaintext, cfb_segment_size, padded_cfb, &pad_len_cfb);
    printf("\n--------------------------------------------------------------------\n");
    printf("3. CIPHER FEEDBACK (CFB) MODE PADDING\n");
    printf("--------------------------------------------------------------------\n");
    printf("Segment Size (s-bits)    : %d bits\n", cfb_segment_size);
    printf("Alignment Status         : %s\n", 
           (pt_len % cfb_segment_size == 0) ? "ALIGNED (Full padding segment appended)" : "UNALIGNED");
    printf("Padding Bits Added       : %d bit(s) [1 followed by %d zero(es)]\n", 
           pad_len_cfb, pad_len_cfb - 1);
    printf("Padded Bitstream         : %s\n", padded_cfb);
    printf("Total Padded Length      : %lu bits (%lu segments)\n", 
           strlen(padded_cfb), strlen(padded_cfb) / cfb_segment_size);
    printf("Partitioned Segments:\n");
    print_blocks(padded_cfb, cfb_segment_size);

    // 6. Security & Design Analysis
    printf("\n====================================================================\n");
    printf("EXPLANATION & ANALYSIS:\n");
    printf("====================================================================\n");
    printf("1. Unambiguous Padding:\n");
    printf("   Appending a full block/segment when the plaintext is already\n");
    printf("   aligned ensures the receiver can ALWAYS distinguish padding from\n");
    printf("   actual plaintext bits without ambiguity.\n");
    printf("2. Unpadding Algorithm:\n");
    printf("   The receiver scans backward from the very last bit:\n");
    printf("     - Drops all trailing '0' bits until the first '1' is reached.\n");
    printf("     - Drops that '1' bit.\n");
    printf("     - The remaining bits represent the original plaintext.\n");
    printf("3. Note on Implementation:\n");
    printf("   This program demonstrates standard padding preprocessing.\n");
    printf("   It is not an encryption implementation.\n");
    printf("====================================================================\n");

    return 0;
}
