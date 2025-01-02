#include <stdio.h>

int main() {
    printf("Hello from the dylib!\n");
    return 0;
}

int RunMain() {
    main();
    return 0;
}