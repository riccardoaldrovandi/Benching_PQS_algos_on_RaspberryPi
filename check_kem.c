#include <stdio.h>
#include <oqs/oqs.h>

int main() {
    int count = OQS_KEM_alg_count();
    for (int i = 0; i < count; i++) {
        printf("Available KEM: %s\n", OQS_KEM_alg_identifier(i));
    }
    return 0;
}
