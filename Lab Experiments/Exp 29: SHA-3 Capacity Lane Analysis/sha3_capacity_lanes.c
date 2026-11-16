/*
 * ============================================================================
 * Experiment 29: SHA-3 Capacity Lane Analysis
 * 
 * Objective:
 *   Analyze the internal state structure of the SHA-3 (Keccak-f[1600]) sponge
 *   construction, compute rate and capacity lane partitions, track the status
 *   of capacity lanes across multiple message block absorptions when the Keccak
 *   permutation is omitted, and contrast this with the real SHA-3 design.
 * 
 * SHA-3 State Architecture:
 *   - Total State Size (b) = 1600 bits
 *   - Lane Size (w)        = 64 bits (b = 25 * w, arranged in a 5x5 array of lanes)
 *   - Rate (r)             = 1024 bits (e.g., for SHA3-224 or standard r=1024)
 *   - Capacity (c)         = b - r = 1600 - 1024 = 576 bits
 *   - Rate Lanes           = r / w = 1024 / 64 = 16 lanes
 *   - Capacity Lanes       = c / w = 576 / 64 = 9 lanes
 * 
 * Sponge Absorption Operation:
 *   In each absorption step, an r-bit message block P_i is XORed into the
 *   first r bits of the state:
 *       State[0 .. r-1] = State[0 .. r-1] XOR P_i
 *       State[r .. b-1] is UNTOUCHED by message injection.
 * 
 * Experiment Condition:
 *   - Do NOT apply the Keccak-f permutation between blocks.
 *   - All rate lanes of incoming blocks contain at least one nonzero bit.
 *   - Capacity lanes start at zero.
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define STATE_BITS 1600
#define LANE_BITS  64
#define TOTAL_LANES (STATE_BITS / LANE_BITS) // 25 lanes

typedef struct {
    uint64_t lanes[TOTAL_LANES]; // 25 lanes (5x5 matrix of 64-bit words)
} KeccakState;

int main(void) {
    int rate_bits = 1024;
    int num_blocks;

    printf("====================================================================\n");
    printf("   EXP 29: SHA-3 INTERNAL STATE & CAPACITY LANE ANALYSIS           \n");
    printf("====================================================================\n\n");

    // 1. Calculations
    int capacity_bits = STATE_BITS - rate_bits;
    int rate_lanes = rate_bits / LANE_BITS;
    int capacity_lanes = capacity_bits / LANE_BITS;

    printf("--------------------------------------------------------------------\n");
    printf("1. SHA-3 STATE ARCHITECTURE CALCULATIONS:\n");
    printf("--------------------------------------------------------------------\n");
    printf("Total State Size (b)        : %d bits\n", STATE_BITS);
    printf("Lane Word Size (w)          : %d bits (uint64_t)\n", LANE_BITS);
    printf("Total Lanes in 5x5 Matrix   : %d lanes (5 x 5 = 25)\n", TOTAL_LANES);
    printf("Block Size / Rate (r)       : %d bits\n", rate_bits);
    printf("Rate Lanes (r / w)          : %d / %d = %d lanes (Lanes 0 to %d)\n",
           rate_bits, LANE_BITS, rate_lanes, rate_lanes - 1);
    printf("Capacity (c = b - r)        : %d - %d = %d bits\n",
           STATE_BITS, rate_bits, capacity_bits);
    printf("Capacity Lanes (c / w)      : %d / %d = %d lanes (Lanes %d to %d)\n",
           capacity_bits, LANE_BITS, capacity_lanes, rate_lanes, TOTAL_LANES - 1);

    // 2. Accept number of message blocks
    printf("\nEnter number of message blocks to absorb (e.g., 5): ");
    if (scanf("%d", &num_blocks) != 1 || num_blocks <= 0) {
        printf("Error: Number of blocks must be a positive integer.\n");
        return 1;
    }

    // 3. Initialize Keccak State
    // All 25 lanes start initialized to 0
    KeccakState state;
    for (int i = 0; i < TOTAL_LANES; i++) {
        state.lanes[i] = 0ULL;
    }

    printf("\n--------------------------------------------------------------------\n");
    printf("2. SIMULATION OF SPONGE ABSORPTION (WITHOUT KECCAK PERMUTATION):\n");
    printf("   Assumption: Rate lanes contain nonzero message bits in each block.\n");
    printf("   Permutation: KECCAK-f[1600] IS NOT APPLIED (per lab specification).\n");
    printf("--------------------------------------------------------------------\n");
    printf(" Block | Rate Lanes (Nonzero) | Capacity Lanes (Zero) | Capacity Zero %%\n");
    printf("-------+----------------------+-----------------------+----------------\n");

    for (int b = 1; b <= num_blocks; b++) {
        // Message block injection: XOR nonzero message bits into rate lanes (0..15)
        for (int i = 0; i < rate_lanes; i++) {
            // Simulated nonzero 64-bit message block word
            uint64_t msg_word = 0xA5A5A5A500000000ULL | (uint64_t)b;
            state.lanes[i] ^= msg_word;
        }

        // Capacity lanes (16..24) are NOT touched by message injection
        // And Keccak permutation is OMITTED.

        // Count zero and nonzero capacity lanes
        int zero_capacity_count = 0;
        for (int i = rate_lanes; i < TOTAL_LANES; i++) {
            if (state.lanes[i] == 0ULL) {
                zero_capacity_count++;
            }
        }
        double zero_pct = ((double)zero_capacity_count / capacity_lanes) * 100.0;

        printf("  %3d  |       %2d / %2d        |        %2d / %2d         |     %6.1f%%\n",
               b, rate_lanes, rate_lanes, zero_capacity_count, capacity_lanes, zero_pct);
    }

    // 4. Detailed State Matrix Visualization
    printf("\n--------------------------------------------------------------------\n");
    printf("FINAL 5x5 STATE MATRIX LANE STATUS (x=0..4, y=0..4):\n");
    printf("--------------------------------------------------------------------\n");
    for (int y = 0; y < 5; y++) {
        printf("  Row y=%d: ", y);
        for (int x = 0; x < 5; x++) {
            int lane_idx = x + 5 * y;
            if (lane_idx < rate_lanes) {
                printf("[R%02d: NONZERO] ", lane_idx);
            } else {
                printf("[C%02d:   ZERO ] ", lane_idx);
            }
        }
        printf("\n");
    }

    // 5. Theoretical Conclusion & Real SHA-3 Contrast
    printf("\n====================================================================\n");
    printf("OBSERVATIONS & CONCLUSION:\n");
    printf("====================================================================\n");
    printf("1. Experimental Finding:\n");
    printf("   Without the Keccak permutation, message absorption only modifies\n");
    printf("   the %d rate lanes (bits 0 to %d).\n", rate_lanes, rate_bits - 1);
    printf("   The %d capacity lanes (bits %d to %d) are NEVER modified.\n",
           capacity_lanes, rate_bits, STATE_BITS - 1);
    printf("   Therefore, all %d capacity lanes remain identically ZERO indefinitely,\n", capacity_lanes);
    printf("   regardless of how many blocks are absorbed.\n");
    printf("\n2. Purpose of the Keccak-f[1600] Permutation in Real SHA-3:\n");
    printf("   In real SHA-3, every absorption is followed by the Keccak-f[1600]\n");
    printf("   permutation consisting of 24 rounds of 5 mathematical operations:\n");
    printf("     - Theta (parity and diffusion across columns)\n");
    printf("     - Rho   (bit rotations within lanes)\n");
    printf("     - Pi    (lane transposition/permutation)\n");
    printf("     - Chi   (nonlinear bit mixing along rows)\n");
    printf("     - Iota  (round constant injection to break symmetry)\n");
    printf("   The permutation rapidly diffuses rate bits across ALL 25 lanes,\n");
    printf("   ensuring zero lanes vanish completely after just one round.\n");
    printf("====================================================================\n");

    return 0;
}
