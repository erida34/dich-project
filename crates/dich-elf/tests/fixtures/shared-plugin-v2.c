extern int shared_value(void);
__attribute__((visibility("default"))) int plugin_value(void) { return shared_value() + 2; }
