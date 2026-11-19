// Force-included (-include) into upstream's stale AFL harness test/afl_digest_test/
// afl_mysql_query_digest.cpp. The harness passes its AFL testcase buffer as `unsigned char*`;
// the tokenizer API took `const char*` since, which g++ -fpermissive tolerated and clang rejects.
// This overload only converts the pointer type and calls the real tokenizer entry point.
#pragma once
#include "c_tokenizer.h"
static inline char* mysql_query_digest_and_first_comment_2(const unsigned char* q, int q_len,
		char** const fst_cmnt, char* const buf) {
	return mysql_query_digest_and_first_comment_2((const char*)q, q_len, fst_cmnt, buf);
}
