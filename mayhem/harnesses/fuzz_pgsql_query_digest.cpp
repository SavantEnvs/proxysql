// libFuzzer target: ProxySQL's PostgreSQL query digest tokenizer (lib/pgsql_tokenizer.cpp), run
// on every client 'Q'/Parse query. Calls pgsql_query_digest_and_first_comment() exactly as
// Query_Processor.cpp qp_digest_legacy() does (128-byte buffer only when
// pgsql_query_digest_buffer_size() says it fits), then the scanners Query_Processor and the
// PgSQL session run on the query and its digest.
#include <stdlib.h>
#include <string.h>
#include "query_digest_common.h"

extern __thread int  pgsql_thread___query_digests_max_query_length;
extern __thread bool pgsql_thread___query_digests_lowercase;
extern __thread bool pgsql_thread___query_digests_replace_null;
extern __thread bool pgsql_thread___query_digests_no_digits;
extern __thread int  pgsql_thread___query_digests_grouping_limit;
extern __thread int  pgsql_thread___query_digests_groups_grouping_limit;
extern __thread bool pgsql_thread___query_digests_keep_comment;

static void release(char* digest, char* buf, char* first_comment) {
	if (digest != buf) free(digest);
	free(first_comment);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	if (size < 3) return -1;
	options opts = mayhem_digest_options(data);
	int q_len = (int)(size - 3);
	// NUL-terminated heap copy: the scanners below take C strings, like the session's query text.
	char* query = (char*)malloc(q_len + 1);
	memcpy(query, data + 3, q_len);
	query[q_len] = 0;

	char buf[MAYHEM_QUERY_DIGEST_BUF];
	char* fc = NULL;
	char* b = (pgsql_query_digest_buffer_size(q_len, &opts) <= MAYHEM_QUERY_DIGEST_BUF) ? buf : NULL;
	char* d = pgsql_query_digest_and_first_comment(query, q_len, &fc, b, &opts);
	if (d) {
		pgsql_query_scan(d, query);
		pgsql_digest_scan(d);
	}
	release(d, b, fc);

	pgsql_thread___query_digests_max_query_length = opts.max_query_length;
	pgsql_thread___query_digests_lowercase = opts.lowercase;
	pgsql_thread___query_digests_replace_null = opts.replace_null;
	pgsql_thread___query_digests_no_digits = opts.replace_number;
	pgsql_thread___query_digests_grouping_limit = opts.grouping_limit;
	pgsql_thread___query_digests_groups_grouping_limit = opts.groups_grouping_limit;
	pgsql_thread___query_digests_keep_comment = opts.keep_comment;

	// Same buffer contract as above: _2 builds the same options from these settings.
	fc = NULL; d = pgsql_query_digest_and_first_comment_2(query, q_len, &fc, b);
	release(d, b, fc);

	char* full = pgsql_query_full_digest(query);
	free(full);
	pgsql_text_find_words(query, q_len);
	const char* lost = NULL;
	for (const char* s = query; s && *s; ) {
		const char* n = pgsql_digest_next_stmt(s, &lost);
		if (!n || n <= s) break;
		s = n;
	}
	free(query);
	return 0;
}
