__attribute__((constructor)) static void dich_fixture_init(void) {}

__attribute__((visibility("default"))) int dich_fixture_value(void) {
    return 42;
}
