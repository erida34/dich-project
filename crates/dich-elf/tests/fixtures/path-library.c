static const char dich_fixture_path[] = "/etc/dich-fixture.conf";

__attribute__((visibility("default"))) char dich_fixture_path_first(void) {
    return dich_fixture_path[0];
}
