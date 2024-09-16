#include <stdio.h>
#include <stdint.h>
#include <string.h>

void print_ascii(uint64_t value) {
    char    *ascii = (char *)&value;

    for (int i = 0; i < 8; i++) {
        printf("%c", ascii[i]);
    }
}

int main() {
    uint64_t    value;
    char        solution[256];
    int         number_elements = 5;
    char        *addr[] = {
        "0x756e505234376848",
        "0x45414a3561733951",
        "0x377a7143574e6758",
        "0x354a35686e475873",
        "0x48336750664b394d"
    };

    for (int i = 0; i < number_elements; i++) {
        sscanf(addr[i], "0x%lx", &value);
        printf("Original: %s\n", addr[i]);
        printf("ASCII: ");
        print_ascii(value);
        printf("\n\n");
    }

    printf("Final ASCII: ");
    for (int i = 0; i < number_elements; i++) {
        sscanf(addr[i], "0x%lx", &value);
        print_ascii(value);
    }
    printf("\n");

    return 0;
}
