
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

long long powerMod(long long base, long long exp, long long n)
{
    long long result = 1;

    while (exp > 0)
    {
        result = (result * base) % n;
        exp--;
    }

    return result;
}

int isPrime(long long num)
{
    long long i;

    if (num < 2)
        return 0;

    for (i = 2; i * i <= num; i++)
        if (num % i == 0)
            return 0;

    return 1;
}

long long gcd(long long a, long long b)
{
    long long temp;

    while (b != 0)
    {
        temp = b;
        b = a % b;
        a = temp;
    }

    return a;
}

long long findD(long long e, long long phi)
{
    long long d;

    for (d = 1; d < phi; d++)
        if ((e * d) % phi == 1)
            return d;

    return -1;
}

int main(void)
{
    long long p, q, n, phi, e, d;
    long long M, C;
    char input[100];
    int i, isNumber = 1;

    printf("Enter prime number p: ");
    if (scanf("%lld", &p) != 1 || !isPrime(p))
    {
        printf("p must be prime.\n");
        return 1;
    }

    printf("Enter prime number q: ");
    if (scanf("%lld", &q) != 1 || !isPrime(q) || p == q)
    {
        printf("q must be a different prime number.\n");
        return 1;
    }

    n = p * q;
    phi = (p - 1) * (q - 1);

    e = 2;
    while (e < phi && gcd(e, phi) != 1)
        e++;

    if (e >= phi)
    {
        printf("Cannot find valid e.\n");
        return 1;
    }

    d = findD(e, phi);

    if (d == -1)
    {
        printf("Cannot find d.\n");
        return 1;
    }

    printf("\nn = %lld", n);
    printf("\nphi(n) = %lld", phi);
    printf("\nPublic key = (%lld, %lld)", e, n);
    printf("\nPrivate key = (%lld, %lld)\n", d, n);

    printf("\nEnter text or a number: ");
    scanf("%99s", input);

    /* Check whether input contains only digits */
    for (i = 0; input[i] != '\0'; i++)
    {
        if (!isdigit((unsigned char)input[i]))
        {
            isNumber = 0;
            break;
        }
    }

    if (isNumber)
    {
        char *end;
        M = strtoll(input, &end, 10);

        if (*end != '\0' || M < 0 || M >= n)
        {
            printf("Numeric input must be between 0 and %lld.\n", n - 1);
            return 1;
        }

        C = powerMod(M, e, n);
        printf("\nEncrypted number = %lld", C);
        printf("\nDecrypted number = %lld\n", powerMod(C, d, n));
    }
    else
    {
        printf("\nEncrypted text (numeric blocks):\n");

        for (i = 0; input[i] != '\0'; i++)
        {
            unsigned char ch = (unsigned char)input[i];

            /* Split ASCII into two hexadecimal digits */
            int high = ch / 16;
            int low = ch % 16;

            C = powerMod(high, e, n);
            printf("%lld ", C);

            C = powerMod(low, e, n);
            printf("%lld ", C);
        }

        printf("\n\nDecrypted text:\n");

        for (i = 0; input[i] != '\0'; i++)
        {
            unsigned char ch = (unsigned char)input[i];
            int high = ch / 16;
            int low = ch % 16;

            long long c1 = powerMod(high, e, n);
            long long c2 = powerMod(low, e, n);

            high = (int)powerMod(c1, d, n);
            low = (int)powerMod(c2, d, n);

            printf("%c", high * 16 + low);
        }

        printf("\n");
    }

    return 0;
}
