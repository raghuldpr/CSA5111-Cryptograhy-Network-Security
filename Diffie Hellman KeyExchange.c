
#include <stdio.h>

long long powerMod(long long base, long long exp, long long mod)
{
    long long result = 1;

    while (exp > 0)
    {
        result = (result * base) % mod;
        exp--;
    }

    return result;
}

int main()
{
    long long P, G;
    long long a, b;
    long long A, B;
    long long keyA, keyB;

    printf("Enter prime number P: ");
    scanf("%lld", &P);

    printf("Enter primitive root G: ");
    scanf("%lld", &G);

    printf("Enter private key of Alice: ");
    scanf("%lld", &a);

    printf("Enter private key of Bob: ");
    scanf("%lld", &b);

    /* Public keys */
    A = powerMod(G, a, P);
    B = powerMod(G, b, P);

    printf("\nPublic key of Alice: %lld", A);
    printf("\nPublic key of Bob: %lld", B);

    /* Shared secret keys */
    keyA = powerMod(B, a, P);
    keyB = powerMod(A, b, P);

    printf("\n\nShared key calculated by Alice: %lld", keyA);
    printf("\nShared key calculated by Bob: %lld\n", keyB);

    if (keyA == keyB)
        printf("Key exchange successful!\n");
    else
        printf("Key exchange failed!\n");

    return 0;
}

