#include <stdio.h>
#include <unistd.h>
#include <lucid.h>

int main(int argc, char *argv[]) {
    printf("Argument count: %d\n", argc);
    printf("Args:\n");
    for (int i = 0; i < argc; i++) {
        printf("   -%s\n", argv[i]);
    }

    size_t iters = 0;
    while (1) {
        printf("Test alive!\n");
        sleep(1);
        iters++;

        if (iters == 5) { break; }
    }

    printf("g_lucid_ctx: %p\n", g_lucid_ctx);
}