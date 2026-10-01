#include <stdio.h>
#include <stdlib.h>

int main() {
    char *flag = getenv("FLAG");
    if (flag != NULL) {
        printf("%s\n", flag);
    } else {
        printf("FLAG environment variable not set.\n");
    }
    return 0;
}
