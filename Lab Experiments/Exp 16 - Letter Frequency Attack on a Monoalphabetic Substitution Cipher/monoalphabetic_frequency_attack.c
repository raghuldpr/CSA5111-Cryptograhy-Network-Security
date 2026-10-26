#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define ALPHABET_SIZE 26
#define MAX_TEXT_LEN 1024

/* Standard English letters sorted in descending order of typical frequency */
static const char ENGLISH_FREQ_ORDER[] = "ETAOINSHRDLCUMWFGYPBVKJXQZ";

/* Standard English letter frequencies (in percentage) */
static const double ENGLISH_FREQ_PERCENT[ALPHABET_SIZE] = {
    8.12,  /* A */
    1.49,  /* B */
    2.71,  /* C */
    4.32,  /* D */
    12.02, /* E */
    2.30,  /* F */
    2.03,  /* G */
    5.92,  /* H */
    7.31,  /* I */
    0.10,  /* J */
    0.69,  /* K */
    3.98,  /* L */
    2.61,  /* M */
    6.95,  /* N */
    7.68,  /* O */
    1.82,  /* P */
    0.11,  /* Q */
    6.02,  /* R */
    6.28,  /* S */
    9.10,  /* T */
    2.88,  /* U */
    1.11,  /* V */
    2.09,  /* W */
    0.17,  /* X */
    2.11,  /* Y */
    0.07   /* Z */
};

typedef struct {
    char letter;
    int count;
    double percentage;
} FreqEntry;

int compare_freq(const void *a, const void *b) {
    const FreqEntry *fa = (const FreqEntry *)a;
    const FreqEntry *fb = (const FreqEntry *)b;
    if (fb->count != fa->count) {
        return fb->count - fa->count;
    }
    return fa->letter - fb->letter;
}

int main(void) {
    char ciphertext[MAX_TEXT_LEN];
    FreqEntry freq[ALPHABET_SIZE];
    int total_letters = 0;

    printf("====================================================================\n");
    printf("   EXP 16: FREQUENCY ATTACK ON MONOALPHABETIC SUBSTITUTION CIPHER\n");
    printf("====================================================================\n\n");

    printf("Enter ciphertext (press ENTER for verification vector: 'WKH TXLFN EURZQ IRA'):\n> ");
    if (fgets(ciphertext, sizeof(ciphertext), stdin) == NULL) {
        strcpy(ciphertext, "");
    }
    ciphertext[strcspn(ciphertext, "\r\n")] = '\0';

    /* Check if input has alphabetic characters */
    int has_alpha = 0;
    for (int i = 0; ciphertext[i] != '\0'; i++) {
        if (isalpha((unsigned char)ciphertext[i])) {
            has_alpha = 1;
            break;
        }
    }

    if (!has_alpha) {
        strcpy(ciphertext, "WKH TXLFN EURZQ IRA");
        printf("[Using Default Ciphertext]: %s\n", ciphertext);
    }

    /* Initialize frequency table */
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        freq[i].letter = (char)('A' + i);
        freq[i].count = 0;
        freq[i].percentage = 0.0;
    }

    /* Count letter frequencies */
    for (int i = 0; ciphertext[i] != '\0'; i++) {
        if (isalpha((unsigned char)ciphertext[i])) {
            int idx = toupper((unsigned char)ciphertext[i]) - 'A';
            freq[idx].count++;
            total_letters++;
        }
    }

    /* Calculate percentages */
    if (total_letters > 0) {
        for (int i = 0; i < ALPHABET_SIZE; i++) {
            freq[i].percentage = (100.0 * freq[i].count) / total_letters;
        }
    }

    /* Sort by observed frequency in descending order */
    qsort(freq, ALPHABET_SIZE, sizeof(FreqEntry), compare_freq);

    printf("\n--------------------------------------------------------------------\n");
    printf("1. OBSERVED CIPHERTEXT LETTER FREQUENCIES (Descending Order)\n");
    printf("--------------------------------------------------------------------\n");
    printf("Total Alphabetical Characters: %d\n\n", total_letters);
    printf("%-8s | %-6s | %-12s | %s\n", "Letter", "Count", "Observed %", "Expected English %");
    printf("---------+--------+--------------+----------------------------------\n");

    int active_distinct = 0;
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        if (freq[i].count > 0) {
            int orig_idx = freq[i].letter - 'A';
            printf("   %-5c | %-6d | %-11.2f%% | %5.2f%%\n",
                   freq[i].letter, freq[i].count, freq[i].percentage,
                   ENGLISH_FREQ_PERCENT[orig_idx]);
            active_distinct++;
        }
    }

    printf("\nTypical English Frequency Order: %s\n", ENGLISH_FREQ_ORDER);
    printf("Observed Ciphertext Letter Order: ");
    for (int i = 0; i < active_distinct; i++) {
        printf("%c", freq[i].letter);
    }
    printf("\n\n");

    /* Step 2: Pure Naive Frequency Substitution Mapping */
    char sub_map[256];
    for (int i = 0; i < 256; i++) sub_map[i] = (char)i;

    /* Map observed descending letters to ETAOINSHRDLCUMWFGYPBVKJXQZ */
    for (int i = 0; i < active_distinct && i < 26; i++) {
        char c_upper = freq[i].letter;
        char p_upper = ENGLISH_FREQ_ORDER[i];
        sub_map[(unsigned char)c_upper] = p_upper;
        sub_map[(unsigned char)tolower((unsigned char)c_upper)] = (char)tolower((unsigned char)p_upper);
    }

    char naive_plaintext[MAX_TEXT_LEN];
    int len = (int)strlen(ciphertext);
    for (int i = 0; i < len; i++) {
        naive_plaintext[i] = sub_map[(unsigned char)ciphertext[i]];
    }
    naive_plaintext[len] = '\0';

    printf("--------------------------------------------------------------------\n");
    printf("2. HEURISTIC SUBSTITUTION ATTEMPT (Direct Frequency Mapping)\n");
    printf("--------------------------------------------------------------------\n");
    printf("Proposed Mapping: ");
    for (int i = 0; i < active_distinct && i < 10; i++) {
        printf("%c->%c ", freq[i].letter, ENGLISH_FREQ_ORDER[i]);
    }
    printf("...\n");
    printf("Resulting Heuristic Plaintext: \"%s\"\n\n", naive_plaintext);

    /* Step 3: Caesar Shift Demonstration (LMR / Additional Demonstration) */
    printf("--------------------------------------------------------------------\n");
    printf("3. ADDITIONAL DEMONSTRATION: CAESAR/UNIFORM SHIFT ANALYSIS\n");
    printf("--------------------------------------------------------------------\n");
    printf("Note: If the monoalphabetic cipher happens to be a uniform Caesar\n");
    printf("shift, testing the 26 shift values identifies the exact match:\n\n");

    int best_shift = -1;
    double best_shift_score = -1.0;
    char best_shift_text[MAX_TEXT_LEN];

    for (int shift = 0; shift < 26; shift++) {
        char temp_plain[MAX_TEXT_LEN];
        double score = 0.0;
        int count = 0;
        for (int i = 0; ciphertext[i] != '\0'; i++) {
            char ch = ciphertext[i];
            if (isupper((unsigned char)ch)) {
                temp_plain[i] = (char)(((ch - 'A' - shift + 26) % 26) + 'A');
                score += ENGLISH_FREQ_PERCENT[temp_plain[i] - 'A'];
                count++;
            } else if (islower((unsigned char)ch)) {
                temp_plain[i] = (char)(((ch - 'a' - shift + 26) % 26) + 'a');
                score += ENGLISH_FREQ_PERCENT[toupper((unsigned char)temp_plain[i]) - 'A'];
                count++;
            } else {
                temp_plain[i] = ch;
            }
        }
        temp_plain[len] = '\0';
        double avg_score = (count > 0) ? (score / count) : 0.0;
        if (avg_score > best_shift_score) {
            best_shift_score = avg_score;
            best_shift = shift;
            strcpy(best_shift_text, temp_plain);
        }
    }

    printf("Tested Shift Candidates:\n");
    printf("  [Caesar Shift k=%2d] -> \"%s\" (Likelihood Score: %.2f)\n",
           best_shift, best_shift_text, best_shift_score);

    printf("\n--------------------------------------------------------------------\n");
    printf("4. CRYPTANALYTIC EVALUATION & CONCLUSION\n");
    printf("--------------------------------------------------------------------\n");
    printf("1. Single-letter frequency analysis is purely HEURISTIC for general\n");
    printf("   monoalphabetic ciphers. The keyspace is 26! (~4.03 x 10^26).\n");
    printf("2. In short texts (like \"%s\"), sample sizes are far\n", ciphertext);
    printf("   too small for law-of-large-numbers statistical frequency convergence.\n");
    printf("3. Direct frequency substitution produces scrambled text because low-count\n");
    printf("   letters cannot be mapped without bigram/trigram context or dictionary aids.\n");
    printf("4. For the test vector, uniform shift k=3 recovers: \"%s\".\n", best_shift_text);
    printf("   However, this shift approach succeeds ONLY because the test sample\n");
    printf("   is a Caesar cipher subset, not an arbitrary monoalphabetic permutation.\n");
    printf("====================================================================\n");

    return 0;
}
