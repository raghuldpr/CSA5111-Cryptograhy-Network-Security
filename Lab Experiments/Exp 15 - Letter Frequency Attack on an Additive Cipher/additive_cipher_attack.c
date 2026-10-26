#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define ALPHABET_SIZE 26
#define MAX_TEXT_LEN 1024

/* Standard English letter frequencies (in percentage) */
static const double ENGLISH_FREQ[ALPHABET_SIZE] = {
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
    int shift;
    double score;
    char text[MAX_TEXT_LEN];
} Candidate;

/* Decrypt ciphertext using an additive key (shift) */
void decrypt_additive(const char *cipher, int shift, char *plain) {
    int i;
    for (i = 0; cipher[i] != '\0'; i++) {
        char ch = cipher[i];
        if (isupper((unsigned char)ch)) {
            plain[i] = (char)(((ch - 'A' - shift + 26) % 26) + 'A');
        } else if (islower((unsigned char)ch)) {
            plain[i] = (char)(((ch - 'a' - shift + 26) % 26) + 'a');
        } else {
            plain[i] = ch; /* Preserve spaces and punctuation */
        }
    }
    plain[i] = '\0';
}

/* Calculate likelihood score based on English letter frequency matching */
double calculate_likelihood(const char *text) {
    double score = 0.0;
    int letter_count = 0;
    for (int i = 0; text[i] != '\0'; i++) {
        if (isalpha((unsigned char)text[i])) {
            int idx = toupper((unsigned char)text[i]) - 'A';
            score += ENGLISH_FREQ[idx];
            letter_count++;
        }
    }
    return (letter_count > 0) ? (score / letter_count) : 0.0;
}

/* Compare candidates for sorting in descending order of score */
int compare_candidates(const void *a, const void *b) {
    const Candidate *c1 = (const Candidate *)a;
    const Candidate *c2 = (const Candidate *)b;
    if (c2->score > c1->score) return 1;
    if (c2->score < c1->score) return -1;
    return 0;
}

int main(void) {
    char ciphertext[MAX_TEXT_LEN];
    int top_n = 10;
    int letter_freq[ALPHABET_SIZE] = {0};
    int total_letters = 0;
    Candidate candidates[ALPHABET_SIZE];

    printf("====================================================================\n");
    printf("   EXP 15: LETTER FREQUENCY ATTACK ON AN ADDITIVE CIPHER\n");
    printf("====================================================================\n\n");

    printf("Enter ciphertext (press ENTER for default test vector):\n> ");
    if (fgets(ciphertext, sizeof(ciphertext), stdin) == NULL) {
        strcpy(ciphertext, "");
    }
    /* Trim trailing newline */
    ciphertext[strcspn(ciphertext, "\r\n")] = '\0';

    /* Check if input has alphabetic characters; if not, use default test vector */
    int has_alpha = 0;
    for (int i = 0; ciphertext[i] != '\0'; i++) {
        if (isalpha((unsigned char)ciphertext[i])) {
            has_alpha = 1;
            break;
        }
    }

    if (!has_alpha) {
        strcpy(ciphertext, "KHOOR ZRUOG WKLV LV D VHFUHW PHVVDJH IRU WKH ODERUDWRUB HASHULPHQW");
        printf("[Using Default Ciphertext]: %s\n", ciphertext);
    }

    printf("\nEnter number of top candidate plaintexts to display (e.g., 5 to 26, default 10): ");
    char num_buf[32];
    if (fgets(num_buf, sizeof(num_buf), stdin) != NULL && strlen(num_buf) > 1) {
        int val = atoi(num_buf);
        if (val >= 1 && val <= 26) {
            top_n = val;
        }
    }
    printf("Displaying Top %d candidate plaintexts.\n\n", top_n);

    /* Step 1: Count frequency of letters A-Z */
    for (int i = 0; ciphertext[i] != '\0'; i++) {
        if (isalpha((unsigned char)ciphertext[i])) {
            int idx = toupper((unsigned char)ciphertext[i]) - 'A';
            letter_freq[idx]++;
            total_letters++;
        }
    }

    printf("--------------------------------------------------------------------\n");
    printf("1. CIPHERTEXT LETTER FREQUENCY ANALYSIS\n");
    printf("--------------------------------------------------------------------\n");
    printf("Total Alphabetical Characters: %d\n", total_letters);
    printf("Observed Letter Counts:\n");
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        if (letter_freq[i] > 0) {
            printf("[%c: %2d (%.1f%%)] ", 'A' + i, letter_freq[i],
                   (100.0 * letter_freq[i]) / (total_letters > 0 ? total_letters : 1));
            if ((i + 1) % 6 == 0) printf("\n");
        }
    }
    printf("\n\n");

    /* Step 2: Generate all 26 possible decrypted candidates */
    for (int shift = 0; shift < ALPHABET_SIZE; shift++) {
        candidates[shift].shift = shift;
        decrypt_additive(ciphertext, shift, candidates[shift].text);
        candidates[shift].score = calculate_likelihood(candidates[shift].text);
    }

    /* Step 3: Rank candidates by likelihood score */
    qsort(candidates, ALPHABET_SIZE, sizeof(Candidate), compare_candidates);

    printf("--------------------------------------------------------------------\n");
    printf("2. RANKED DECRYPTED CANDIDATES (Top %d of 26)\n", top_n);
    printf("--------------------------------------------------------------------\n");
    printf("%-5s | %-6s | %-8s | %s\n", "Rank", "Shift", "Score", "Decrypted Text Candidate");
    printf("------+--------+----------+-----------------------------------------\n");

    for (int r = 0; r < top_n && r < ALPHABET_SIZE; r++) {
        printf("#%-4d | key=%-2d | %-8.2f | %s\n",
               r + 1, candidates[r].shift, candidates[r].score, candidates[r].text);
    }

    printf("\n--------------------------------------------------------------------\n");
    printf("3. CRYPTANALYTIC CONCLUSION\n");
    printf("--------------------------------------------------------------------\n");
    printf("Top Candidate (#1): Shift Key = %d\n", candidates[0].shift);
    printf("Plaintext: \"%s\"\n\n", candidates[0].text);
    printf("NOTE: Frequency analysis ranks plaintexts by statistical congruence\n");
    printf("with natural English letter distributions. While highly effective for\n");
    printf("sufficiently long messages, it offers a probabilistic ranking rather\n");
    printf("than an absolute guarantee for short or non-standard texts.\n");
    printf("====================================================================\n");

    return 0;
}
