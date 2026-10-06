#include <stdio.h>
#include <string.h>
#include <ctype.h>

int modInverse(int a, int m) {
    int i;
    for (i = 1; i < m; i++) {
        if ((a * i) % m == 1)
            return i;
    }
    return -1;
}

void encrypt(char text[], int a, int b) {
    int i;

    for (i = 0; text[i] != '\0'; i++) {
        if (isalpha(text[i])) {
            char base = isupper(text[i]) ? 'A' : 'a';

            text[i] = ((a * (text[i] - base) + b) % 26) + base;
        }
    }
}

void decrypt(char text[], int a, int b) {
    int i;
    int a_inv = modInverse(a, 26);

    if (a_inv == -1) {
        printf("Invalid key. 'a' must be coprime with 26.\n");
        return;
    }

    for (i = 0; text[i] != '\0'; i++) {
        if (isalpha(text[i])) {
            char base = isupper(text[i]) ? 'A' : 'a';

            int value = text[i] - base;
            value = (a_inv * (value - b + 26)) % 26;

            text[i] = value + base;
        }
    }
}

int main() {
    char text[100];
    int a, b;

    printf("Enter the text: ");
    fgets(text, sizeof(text), stdin);

    text[strcspn(text, "\n")] = '\0';

    printf("Enter key a: ");
    scanf("%d", &a);

    printf("Enter key b: ");
    scanf("%d", &b);

    if (modInverse(a, 26) == -1) {
        printf("Invalid value of a.\n");
        printf("a must be coprime with 26.\n");
        return 0;
    }

    encrypt(text, a, b);
    printf("\nEncrypted text: %s\n", text);

    decrypt(text, a, b);
    printf("Decrypted text: %s\n", text);

    return 0;
}