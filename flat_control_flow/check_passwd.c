#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int check_password(char *passwd)
{
    int i, sum = 0;
    for (i = 0; ; i++)
    {
        if (!passwd[i])
        {
            break;
        }
        sum += passwd[i];
    }
    if (i == 4)
    {
        if (sum == 0x1a1 && passwd[3] > 'c' && passwd[3] < 'e' && passwd[0] == 'b')
        {
            if ((passwd[3] ^ 0xd) == passwd[1])
            {
                return 1;
            }   
            puts("Orz...");
        }
    }
    else
    {
        puts("len error");
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        puts("error");
        return 1;
    }
    if (check_password(argv[1]))
    {
        puts("Congratulation!");
    }
    else
    {
        puts("error");
    }
    return 0;
}