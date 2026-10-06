#include <stdio.h>
#include <string.h>
#include <ctype.h>

void encrypt(char text[], char key[]) {
    int i, j = 0;
    int keyLen = strlen(key);

    for (i = 0; text[i] != '\0'; i++) {
        if (isalpha(text[i])) {
            char base = isupper(text[i]) ? 'A' : 'a';

            text[i] = ((text[i] - base) +
                       (toupper(key[j % keyLen]) - 'A')) % 26 + base;

            j++;
        }
    }
}

void decrypt(char text[], char key[]) {
    int i, j = 0;
    int keyLen = strlen(key);

    for (i = 0; text[i] != '\0'; i++) {
        if (isalpha(text[i])) {
            char base = isupper(text[i]) ? 'A' : 'a';

            text[i] = ((text[i] - base) -
                       (toupper(key[j % keyLen]) - 'A') + 26) % 26 + base;

            j++;
        }
    }
}

int main() {
    char text[100];
    char key[100];

    printf("Enter the text: ");
    fgets(text, sizeof(text), stdin);
    text[strcspn(text, "\n")] = '\0';

    printf("Enter the key: ");
    scanf("%s", key);

    encrypt(text, key);
    printf("\nEncrypted text: %s\n", text);

    decrypt(text, key);
    printf("Decrypted text: %s\n", text);

    return 0;
}