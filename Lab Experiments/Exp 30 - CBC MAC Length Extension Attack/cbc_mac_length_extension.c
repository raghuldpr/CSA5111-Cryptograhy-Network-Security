/*
 * ============================================================================
 * Experiment 30: CBC-MAC Length Extension Attack
 * 
 * Objective:
 *   Demonstrate the classical length-extension vulnerability of basic CBC-MAC
 *   on variable-length messages when applied to a single-block message.
 * 
 * Cryptographic Background:
 *   Basic CBC-MAC is proven secure ONLY for messages of a fixed, predetermined
 *   number of blocks. When variable-length messages are permitted without
 *   length-prefixing or key separation, an attacker can construct a valid
 *   two-block message with the EXACT same MAC tag without knowing the key.
 * 
 * Mathematical Formulation of the Attack:
 *   1. Let X be an 8-bit single-block message, and IV = 0.
 *   2. Sender computes the MAC tag for message X:
 *        T = MAC(K, X) = E(K, X XOR IV) = E(K, X)
 *   3. Attacker intercepts pair (X, T) without knowing secret key K.
 *   4. Attacker constructs a forged two-block message M' = B1 || B2:
 *        B1 = X
 *        B2 = X XOR T
 *   5. Verifier computes CBC-MAC on M' = B1 || B2:
 *        C1 = E(K, B1 XOR 0) = E(K, X) = T
 *        C2 = E(K, B2 XOR C1) = E(K, (X XOR T) XOR T)
 *           = E(K, X XOR (T XOR T))
 *           = E(K, X XOR 0) = E(K, X) = T
 *   6. Hence, MAC(K, X || (X XOR T)) = T = MAC(K, X)!
 *      The forged message is accepted as authentic with zero knowledge of K!
 * 
 * NOTE ON CIPHER:
 *   For educational clarity, an illustrative 8-bit reversible substitution
 *   cipher E(K, M) = (M + K) mod 256 is used.
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// Educational, illustrative 8-bit block cipher
// E(K, M) = (M + K) mod 256
// NOTE: For demonstration purposes only. Not cryptographically secure.
uint8_t illustrative_encrypt(uint8_t key, uint8_t message) {
    return (uint8_t)(((uint16_t)message + (uint16_t)key) % 256);
}

// Computes CBC-MAC over an array of 8-bit blocks with IV = 0
uint8_t compute_cbc_mac(uint8_t key, const uint8_t *blocks, int num_blocks) {
    uint8_t state = 0; // IV = 0
    for (int i = 0; i < num_blocks; i++) {
        uint8_t xor_input = blocks[i] ^ state;
        state = illustrative_encrypt(key, xor_input);
    }
    return state;
}

void print_binary8(uint8_t val) {
    for (int i = 7; i >= 0; i--) {
        putchar((val & (1 << i)) ? '1' : '0');
    }
}

int main(void) {
    int key_in, x_in;

    printf("====================================================================\n");
    printf("   EXP 30: CBC-MAC LENGTH EXTENSION FORGERY ATTACK                 \n");
    printf("====================================================================\n\n");

    // 1. Accept Key and One-Block Message X
    printf("Enter 8-bit Secret Key K (0..255) (e.g., 37) : ");
    if (scanf("%d", &key_in) != 1 || key_in < 0 || key_in > 255) {
        printf("Error: Key must be in range 0..255.\n");
        return 1;
    }

    printf("Enter 8-bit Message Block X (0..255) (e.g., 100): ");
    if (scanf("%d", &x_in) != 1 || x_in < 0 || x_in > 255) {
        printf("Error: Message block X must be in range 0..255.\n");
        return 1;
    }

    uint8_t key = (uint8_t)key_in;
    uint8_t X = (uint8_t)x_in;

    // 2. Compute Original MAC for One-Block Message X
    uint8_t msg1[1] = {X};
    uint8_t T = compute_cbc_mac(key, msg1, 1);

    printf("\n--------------------------------------------------------------------\n");
    printf("1. LEGITIMATE TRANSMISSION (ONE-BLOCK MESSAGE):\n");
    printf("--------------------------------------------------------------------\n");
    printf("Secret Key K               : %u (binary: ", key); print_binary8(key); printf(")\n");
    printf("Message Block X            : %u (binary: ", X); print_binary8(X); printf(")\n");
    printf("Illustrative Cipher Func   : E(K, M) = (M + K) mod 256\n");
    printf("CBC-MAC Calculation (IV=0) : C1 = E(%u, %u XOR 0) = (%u + %u) mod 256 = %u\n",
           key, X, X, key, T);
    printf("Original Authentication Tag: T = %u (binary: ", T); print_binary8(T); printf(")\n");

    // 3. Attacker Constructs Forged Two-Block Message
    uint8_t Y = X ^ T;
    uint8_t forged_msg[2] = {X, Y};

    printf("\n--------------------------------------------------------------------\n");
    printf("2. ATTACKER'S FORGERY WITHOUT KNOWING SECRET KEY K:\n");
    printf("--------------------------------------------------------------------\n");
    printf("Attacker knows only public/intercepted pair (X=%u, T=%u)\n", X, T);
    printf("Attacker constructs second block: Y = X XOR T\n");
    printf("  X       : "); print_binary8(X); printf(" (%u)\n", X);
    printf("  XOR T   : "); print_binary8(T); printf(" (%u)\n", T);
    printf("  ------------------------\n");
    printf("  Y       : "); print_binary8(Y); printf(" (%u)\n", Y);
    printf("\nConstructed Two-Block Message: M' = X || Y = [%u, %u]\n", forged_msg[0], forged_msg[1]);

    // 4. Verifier Validates the Forged Message
    printf("\n--------------------------------------------------------------------\n");
    printf("3. RECEIVER VERIFICATION OF FORGED TWO-BLOCK MESSAGE:\n");
    printf("--------------------------------------------------------------------\n");
    // Step-by-step verification
    uint8_t C1 = illustrative_encrypt(key, X ^ 0);
    uint8_t in2 = Y ^ C1;
    uint8_t C2 = illustrative_encrypt(key, in2);

    printf("Block 1 (X = %u):\n", X);
    printf("  Input to cipher          : X XOR IV = %u XOR 0 = %u\n", X, X);
    printf("  Cipher output C1         : E(%u, %u) = %u (equals T)\n", key, X, C1);
    printf("Block 2 (Y = %u):\n", Y);
    printf("  Input to cipher          : Y XOR C1 = (%u XOR %u) = %u (equals X!)\n", 
           Y, C1, in2);
    printf("  Cipher output C2         : E(%u, %u) = %u\n", key, in2, C2);
    printf("\n--> Resulting CBC-MAC Tag  : T' = %u\n", C2);

    // 5. Verification Check
    printf("\n====================================================================\n");
    printf("FORGERY ATTACK VERIFICATION RESULT:\n");
    printf("====================================================================\n");
    printf("Original Message Tag T     : %u\n", T);
    printf("Forged Two-Block Tag T'    : %u\n", C2);

    if (T == C2) {
        printf("[SUCCESS] LENGTH-EXTENSION FORGERY SUCCESSFUL!\n");
        printf("The attacker successfully generated a valid 2-block message\n");
        printf("with tag %u without ever possessing the secret key K = %u!\n", T, key);
    } else {
        printf("[FAILED] Forgery failed.\n");
    }

    // 6. Security Analysis
    printf("\n====================================================================\n");
    printf("SECURITY IMPLICATIONS & MITIGATION:\n");
    printf("====================================================================\n");
    printf("1. Root Cause:\n");
    printf("   Basic CBC-MAC is insecure across variable message lengths because\n");
    printf("   the intermediate state C1 is exposed as the tag T of the 1st block.\n");
    printf("   By choosing the second block as (X XOR T), the XOR operation neatly\n");
    printf("   cancels out C1, resetting the cipher input back to X.\n");
    printf("\n2. Countermeasures:\n");
    printf("   - Prepend message length to the first block before MAC computation.\n");
    printf("   - Encrypt the final output block with a second, distinct key.\n");
    printf("   - Use standardized CMAC (NIST SP 800-38B), which derives distinct\n");
    printf("     subkeys K1 and K2 for the final block to prevent extension attacks.\n");
    printf("====================================================================\n");

    return 0;
}
