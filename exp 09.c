
#include <stdio.h>
#include <math.h>

int main()
{
    int i;
    long double keys = 1.0L;
    long double uniqueKeys;

    for (i = 1; i <= 25; i++)
    {
        keys = keys * i;
    }

    uniqueKeys = keys / 25.0L;

    printf("Part (a): Possible Playfair keys\n");
    printf("Total keys (25!) = %.6Le\n", keys);
    printf("Approximate power of 2 = 2^%.2Lf\n",
           log2l(keys));

    printf("\nPart (b): Effectively unique keys\n");
    printf("Unique keys (24!) = %.6Le\n", uniqueKeys);
    printf("Approximate power of 2 = 2^%.2Lf\n",
           log2l(uniqueKeys));

    return 0;
}
