#include <dlfcn.h>

int main(void) {
    return dlopen("liboptional-runtime-probe.so", RTLD_LAZY) == 0;
}
