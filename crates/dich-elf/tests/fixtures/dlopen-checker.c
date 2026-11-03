#include <dlfcn.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) return 3;
    int (*value)(void) = (int (*)(void)) dlsym(handle, "dich_fixture_value");
    if (value == NULL) return 4;
    return value() == 42 ? 0 : 5;
}
