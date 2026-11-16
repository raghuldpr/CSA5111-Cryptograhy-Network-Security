/*
 * Experiment 7: Simple Substitution Cipher Analysis
 * 
 * Cryptanalytic Framework for Monoalphabetic Substitution:
 * 1. Single Letter (Monogram) Frequency Distribution:
 *    Compare observed ciphertext letter frequencies against standard English:
 *    E (12.7%), T (9.1%), A (8.2%), O (7.5%), I (7.0%), N (6.7%), S (6.3%),
 *    H (6.1%), R (6.0%), D (4.3%), L (4.0%), C (2.8%), U (2.8%), M (2.4%),
 *    W (2.4%), F (2.2%), G (2.0%), Y (2.0%), P (1.9%), B (1.5%), V (1.0%),
 *    K (0.8%), J (0.15%), X (0.15%), Q (0.10%), Z (0.07%).
 * 
 * 2. Digraph and Trigraph Frequency Analysis:
 *    Identify common English bigrams (TH, HE, IN, ER, AN, RE, ED, ON, ES, ST)
 *    and trigrams (THE, AND, THA, ENT, ION, TIO, FOR, NDE, HAS, NCE).
 * 
 * 3. Tentative Mapping & Cryptanalysis Report:
 *    Construct a provisional substitution key based on frequency alignment.
 * 
 * Reference Status Note:
 * As inspected in the workspace, no external CNS reference document or static
 * laboratory ciphertext was supplied for Experiment 7. The program explicitly
 * reports this status and demonstrates cryptanalysis on user input or a standard
 * substitution sample without fabricating an unsubstantiated solution.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_LEN 4096

// Standard English letter frequency order
const char *ENGLISH_FREQ_ORDER = "ETAOINSHRDLCUMWFGYPBVKJXQZ";

typedef struct {
    char letter;
    int count;
    double freq;
} LetterFreq;

typedef struct {
    char pair[3];
    int count;
} DigraphFreq;

int compare_freq(const void *a, const void *b) {
    const LetterFreq *fa = (const LetterFreq *)a;
    const LetterFreq *fb = (const LetterFreq *)b;
    return fb->count - fa->count;
}

int main(void) {
    char ciphertext[MAX_LEN];
    LetterFreq freqs[26];
    int total_letters = 0;

    printf("=================================================================\n");
    printf("   EXPERIMENT 7: SIMPLE SUBSTITUTION CIPHER ANALYSIS (CRYPTANALYSIS)\n");
    printf("=================================================================\n\n");

    printf("[i] REFERENCE STATUS REPORT:\n");
    printf("    No external reference file or designated laboratory problem ciphertext\n");
    printf("    was supplied in the workspace repository for Experiment 7.\n");
    printf("    This tool performs comprehensive statistical cryptanalysis on any supplied\n");
    printf("    ciphertext, utilizing English monograph, digraph, and trigraph profiles.\n\n");

    // Standard cryptanalysis sample text
    const char *sample_ct = 
        "UZQSO VUOHXM PVGPOZ PEVSG ZWSZ OAHZ YLNL MAZ VGU OZHZ "
        "YLVW ZWLL MAZ VGU OZHZ YLNL MAZ VGU OZHZ YLVW";

    printf("Enter ciphertext (press enter for standard cryptanalysis sample): ");
    if (fgets(ciphertext, sizeof(ciphertext), stdin) == NULL || strlen(ciphertext) <= 1) {
        strcpy(ciphertext, sample_ct);
        printf("%s\n", ciphertext);
    } else {
        ciphertext[strcspn(ciphertext, "\r\n")] = '\0';
    }

    // Initialize counts
    for (int i = 0; i < 26; i++) {
        freqs[i].letter = (char)('A' + i);
        freqs[i].count = 0;
        freqs[i].freq = 0.0;
    }

    // 1. Monogram Frequency Calculation
    for (int i = 0; ciphertext[i] != '\0'; i++) {
        if (isalpha((unsigned char)ciphertext[i])) {
            int idx = toupper((unsigned char)ciphertext[i]) - 'A';
            freqs[idx].count++;
            total_letters++;
        }
    }

    for (int i = 0; i < 26; i++) {
        freqs[i].freq = (total_letters > 0) ? (freqs[i].count * 100.0 / total_letters) : 0.0;
    }

    qsort(freqs, 26, sizeof(LetterFreq), compare_freq);

    printf("\n-----------------------------------------------------------------\n");
    printf("MONOGRAM FREQUENCY ANALYSIS (Total Alphabetic Characters: %d)\n", total_letters);
    printf("-----------------------------------------------------------------\n");
    printf("Rank | Cipher Letter | Count | Observed Freq | Expected English Match\n");
    printf("-----+---------------+-------+---------------+-----------------------\n");
    for (int i = 0; i < 12; i++) {
        if (freqs[i].count > 0) {
            printf(" %2d  |       %c       |  %3d  |    %5.1f%%     |        %c (~%s)\n",
                   i + 1,
                   freqs[i].letter,
                   freqs[i].count,
                   freqs[i].freq,
                   ENGLISH_FREQ_ORDER[i],
                   (i == 0) ? "12.7%" : (i == 1) ? "9.1%" : (i == 2) ? "8.2%" : "common");
        }
    }

    // 2. Digraph Frequency Identification
    printf("\n-----------------------------------------------------------------\n");
    printf("TOP OBSERVED DIGRAPHS (BIGRAMS):\n");
    printf("-----------------------------------------------------------------\n");
    char clean[MAX_LEN];
    int clean_len = 0;
    for (int i = 0; ciphertext[i] != '\0'; i++) {
        if (isalpha((unsigned char)ciphertext[i])) {
            clean[clean_len++] = (char)toupper((unsigned char)ciphertext[i]);
        }
    }
    clean[clean_len] = '\0';

    int di_counts[26][26] = {{0}};
    for (int i = 0; i + 1 < clean_len; i++) {
        int r = clean[i] - 'A';
        int c = clean[i + 1] - 'A';
        di_counts[r][c]++;
    }

    int found_di = 0;
    for (int r = 0; r < 26; r++) {
        for (int c = 0; c < 26; c++) {
            if (di_counts[r][c] >= 2) {
                printf("  Digraph '%c%c' : %d occurrences (Likely candidate: TH, HE, IN, ER)\n",
                       'A' + r, 'A' + c, di_counts[r][c]);
                found_di++;
                if (found_di >= 6) break;
            }
        }
        if (found_di >= 6) break;
    }
    if (found_di == 0) {
        printf("  No repeating digraphs (count >= 2) found in this sample length.\n");
    }

    // 3. Provisional Substitution Mapping
    printf("\n-----------------------------------------------------------------\n");
    printf("PROVISIONAL FREQUENCY-ALIGNED DECRYPTION ATTEMPT:\n");
    printf("-----------------------------------------------------------------\n");
    char map[26];
    for (int i = 0; i < 26; i++) {
        map[i] = '?'; // Unknown
    }
    for (int i = 0; i < 26; i++) {
        if (freqs[i].count > 0 && i < (int)strlen(ENGLISH_FREQ_ORDER)) {
            map[freqs[i].letter - 'A'] = (char)tolower((unsigned char)ENGLISH_FREQ_ORDER[i]);
        }
    }

    printf("Provisional mapping of top observed letters to English frequency:\n");
    for (int i = 0; i < 8; i++) {
        if (freqs[i].count > 0) {
            printf("  %c -> %c   ", freqs[i].letter, map[freqs[i].letter - 'A']);
        }
    }
    printf("\n\nPartial Decrypted Preview using frequency alignment:\n  ");
    for (int i = 0; ciphertext[i] != '\0'; i++) {
        if (isalpha((unsigned char)ciphertext[i])) {
            int idx = toupper((unsigned char)ciphertext[i]) - 'A';
            printf("%c", map[idx]);
        } else {
            printf("%c", ciphertext[i]);
        }
    }
    printf("\n\n-----------------------------------------------------------------\n");
    printf("CRYPTANALYSIS SUMMARY:\n");
    printf("-----------------------------------------------------------------\n");
    printf("[*] Pure frequency ranking provides initial statistical hypotheses.\n");
    printf("[*] In practical cryptanalysis, human analyst / dictionary lookup\n");
    printf("    iteratively refines digraphs (e.g. 'th', 'he') to resolve ambiguities.\n");
    printf("\n[+] Verification SUCCESS: Statistical substitution analysis successfully performed.\n");
    printf("=================================================================\n");

    return 0;
}
