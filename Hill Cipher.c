#include <stdio.h>
#include <string.h>
#include <ctype.h>

/* Find modular inverse of a modulo 26 */
int modInverse(int a)
{
    int x;

    a = (a % 26 + 26) % 26;

    for (x = 1; x < 26; x++)
    {
        if ((a * x) % 26 == 1)
            return x;
    }

    return -1;
}

int main()
{
    int key[2][2];
    int inverse[2][2];

    char text[100];

    int choice;
    int i, j;
    int det, detInv;

    /* Input key matrix */
    printf("Enter 2x2 key matrix:\n");

    scanf("%d %d", &key[0][0], &key[0][1]);
    scanf("%d %d", &key[1][0], &key[1][1]);

    /* Calculate determinant */
    det = key[0][0] * key[1][1]
        - key[0][1] * key[1][0];

    /* Convert determinant to positive modulo 26 */
    det = (det % 26 + 26) % 26;

    /* Find inverse of determinant */
    detInv = modInverse(det);

    /* Check whether key is valid */
    if (detInv == -1)
    {
        printf("Invalid key!\n");
        printf("Determinant has no inverse modulo 26.\n");
        return 0;
    }

    printf("\n1. Encryption\n");
    printf("2. Decryption\n");
    printf("Enter choice: ");
    scanf("%d", &choice);

    printf("Enter text: ");
    scanf("%s", text);

    /* Convert text to uppercase */
    for (i = 0; text[i] != '\0'; i++)
    {
        text[i] = toupper(text[i]);
    }

    /* ================= ENCRYPTION ================= */

    if (choice == 1)
    {
        int len = strlen(text);

        /* Add X if number of letters is odd */
        if (len % 2 != 0)
        {
            text[len] = 'X';
            text[len + 1] = '\0';
        }

        /* Process two letters at a time */
        for (i = 0; text[i] != '\0'; i += 2)
        {
            int x = text[i] - 'A';
            int y = text[i + 1] - 'A';

            int a = (key[0][0] * x +
                     key[0][1] * y) % 26;

            int b = (key[1][0] * x +
                     key[1][1] * y) % 26;

            text[i] = a + 'A';
            text[i + 1] = b + 'A';
        }

        printf("\nEncrypted text: %s\n", text);
    }

    /* ================= DECRYPTION ================= */

    else if (choice == 2)
    {
        /*
            K^-1 = det^-1 ×
                   [ d  -b ]
                   [ -c  a ]
        */

        inverse[0][0] =
            (detInv * key[1][1]) % 26;

        inverse[0][1] =
            (detInv * (-key[0][1])) % 26;

        inverse[1][0] =
            (detInv * (-key[1][0])) % 26;

        inverse[1][1] =
            (detInv * key[0][0]) % 26;

        /*
            Make all inverse matrix values
            positive and between 0 and 25.
        */

        for (i = 0; i < 2; i++)
        {
            for (j = 0; j < 2; j++)
            {
                inverse[i][j] =
                    (inverse[i][j] % 26 + 26) % 26;
            }
        }

        printf("\nDeterminant mod 26 = %d\n", det);
        printf("Determinant inverse = %d\n", detInv);

        printf("\nInverse key matrix:\n");

        printf("%d %d\n",
               inverse[0][0],
               inverse[0][1]);

        printf("%d %d\n",
               inverse[1][0],
               inverse[1][1]);

        /* Decrypt two letters at a time */
        for (i = 0; text[i] != '\0'; i += 2)
        {
            int x = text[i] - 'A';
            int y = text[i + 1] - 'A';

            int a = (inverse[0][0] * x +
                     inverse[0][1] * y) % 26;

            int b = (inverse[1][0] * x +
                     inverse[1][1] * y) % 26;

            text[i] = a + 'A';
            text[i + 1] = b + 'A';
        }

        printf("\nDecrypted text: %s\n", text);
    }

    else
    {
        printf("Invalid choice!\n");
    }

    return 0;
}
