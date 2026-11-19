// mayhem shim for the standalone build of upstream unit tests and fuzz harnesses: the per-thread
// query-digest settings that lib/c_tokenizer.cpp and lib/pgsql_tokenizer.cpp read (defined by
// MySQL_Thread.cpp / PgSQL_Thread.cpp in the full build) with those files' defaults, plus test_init_minimal().
__thread int  mysql_thread___query_digests_max_query_length = 65000;
__thread bool mysql_thread___query_digests_lowercase = false;
__thread bool mysql_thread___query_digests_replace_null = false;
__thread bool mysql_thread___query_digests_no_digits = false;
__thread int  mysql_thread___query_digests_grouping_limit = 3;
__thread int  mysql_thread___query_digests_groups_grouping_limit = 10;
__thread bool mysql_thread___query_digests_keep_comment = false;
__thread int  pgsql_thread___query_digests_max_query_length = 65000;
__thread bool pgsql_thread___query_digests_lowercase = false;
__thread bool pgsql_thread___query_digests_replace_null = false;
__thread bool pgsql_thread___query_digests_no_digits = false;
__thread int  pgsql_thread___query_digests_grouping_limit = 3;
__thread int  pgsql_thread___query_digests_groups_grouping_limit = 10;
__thread bool pgsql_thread___query_digests_keep_comment = false;
int test_init_minimal() { return 0; }
void test_cleanup_minimal() {}

// test/tap/tap/tap.cpp's exit_status() reports on the "noise" background load generators of
// test/tap/tap/noise_utils.cpp, which need a live MySQL/PgSQL client stack. The unit tests run
// here start no noise tools, so these are the empty values that file has before any is started.
#include <mutex>
#include <string>
#include <vector>
std::vector<std::string> noise_failures;
std::mutex noise_failure_mutex;
extern "C" void stop_noise_tools() {}
extern "C" int get_noise_tools_count() { return 0; }
