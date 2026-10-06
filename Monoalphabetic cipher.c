#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define SIZE 200

// Function to encrypt the plaintext using a 26-letter key
void encrypt(char* text, const char* key) {
    for (int i = 0; text[i] != '\0'; i++) {
        if (isupper(text[i])) {
            // Find alphabetical index (0-25) and map to uppercase key
            text[i] = toupper(key[text[i] - 'A']);
        } else if (islower(text[i])) {
            // Find alphabetical index (0-25) and map to lowercase key
            text[i] = tolower(key[text[i] - 'a']);
        }
    }
}

// Function to decrypt the ciphertext by reversing the key mapping
void decrypt(char* text, const char* key) {
    for (int i = 0; text[i] != '\0'; i++) {
        if (isupper(text[i])) {
            // Find the character's position inside the key array
            for (int j = 0; j < 26; j++) {
                if (toupper(key[j]) == text[i]) {
                    text[i] = 'A' + j;
                    break;
                }
            }
        } else if (islower(text[i])) {
            // Find the character's position inside the key array
            for (int j = 0; j < 26; j++) {
                if (tolower(key[j]) == text[i]) {
                    text[i] = 'a' + j;
                    break;
                }
            }
        }
    }
}

int main() {
    char text[SIZE];
    // Example substitution key mapping A->Q, B->W, C->E, etc.
    char key[27] = "QWERTYUIOPASDFGHJKLZXCVBNM"; 
    
    printf("--- Monoalphabetic Cipher Implementation ---\n");
    printf("Using Key Mapping: %s\n\n", key);

    printf("Enter plaintext message: ");
    fgets(text, SIZE, stdin);
    
    // Remove newline character added by fgets if present
    text[strcspn(text, "\n")] = '\0';

    // 1. Encryption
    encrypt(text, key);
    printf("Encrypted Ciphertext: %s\n", text);

    // 2. Decryption
    decrypt(text, key);
    printf("Decrypted Plaintext:  %s\n", text);

    return 0;
}
