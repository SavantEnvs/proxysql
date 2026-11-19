// mayhem shim: the tokenizer/PROXY-protocol unit tests only call test_init_minimal(), whose job in
// the full build is to set up libproxysql globals those units never touch.
#ifndef MAYHEM_SHIM_TEST_INIT_H
#define MAYHEM_SHIM_TEST_INIT_H
int test_init_minimal();
void test_cleanup_minimal();
#endif
