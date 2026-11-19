// libFuzzer target: ProxySQL's MySQL query digest tokenizer (lib/c_tokenizer.cpp), which runs on
// every client COM_QUERY before query rules. Calls it exactly as Query_Processor.cpp
// qp_digest_legacy() does (fixed 128-byte buffer for short queries, heap otherwise), then the
// staged/one-iteration variants that share the same per-thread settings.
#include <stdlib.h>
#include <string.h>
#include "query_digest_common.h"

extern __thread int  mysql_thread___query_digests_max_query_length;
extern __thread bool mysql_thread___query_digests_lowercase;
extern __thread bool mysql_thread___query_digests_replace_null;
extern __thread bool mysql_thread___query_digests_no_digits;
extern __thread int  mysql_thread___query_digests_grouping_limit;
extern __thread int  mysql_thread___query_digests_groups_grouping_limit;
extern __thread bool mysql_thread___query_digests_keep_comment;

static void release(char* digest, char* buf, char* first_comment) {
	if (digest != buf) free(digest);
	free(first_comment);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	if (size < 3) return -1;
	options opts = mayhem_digest_options(data);
	const char* q = (const char*)data + 3;
	int q_len = (int)(size - 3);
	// Heap copy so ASan sees the exact end of the query buffer.
	char* query = (char*)malloc(q_len ? q_len : 1);
	memcpy(query, q, q_len);

	char buf[MAYHEM_QUERY_DIGEST_BUF];
	char* fc = NULL;
	char* b = (q_len < MAYHEM_QUERY_DIGEST_BUF) ? buf : NULL;
	char* d = mysql_query_digest_and_first_comment(query, q_len, &fc, b, &opts);
	release(d, b, fc);

	// The _2 / staged / one_it variants read the per-thread settings; set them per input.
	mysql_thread___query_digests_max_query_length = opts.max_query_length;
	mysql_thread___query_digests_lowercase = opts.lowercase;
	mysql_thread___query_digests_replace_null = opts.replace_null;
	mysql_thread___query_digests_no_digits = opts.replace_number;
	mysql_thread___query_digests_grouping_limit = opts.grouping_limit;
	mysql_thread___query_digests_groups_grouping_limit = opts.groups_grouping_limit;
	mysql_thread___query_digests_keep_comment = opts.keep_comment;

	fc = NULL; d = mysql_query_digest_and_first_comment_2(query, q_len, &fc, b);
	release(d, b, fc);
	fc = NULL; d = mysql_query_digest_first_stage(query, q_len, &fc, b);
	release(d, b, fc);
	fc = NULL; d = mysql_query_digest_second_stage(query, q_len, &fc, b);
	release(d, b, fc);

	free(query);
	return 0;
}
