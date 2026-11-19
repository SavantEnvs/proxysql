// Shared by fuzz_mysql_query_digest.cpp / fuzz_pgsql_query_digest.cpp.
// Input layout: byte 0 = option flags, byte 1 = grouping limits, byte 2 = max_query_length
// selector, rest = the client query text exactly as it arrives in COM_QUERY / 'Q' (not
// NUL-terminated; the tokenizers take an explicit length).
#pragma once
#include <stddef.h>
#include <stdint.h>
#include "c_tokenizer.h"

#define MAYHEM_QUERY_DIGEST_BUF 128  // QUERY_DIGEST_BUF in include/proxysql_structs.h

static inline options mayhem_digest_options(const uint8_t* data) {
	options o;
	o.lowercase      = data[0] & 1;
	o.replace_null   = data[0] & 2;
	o.replace_number = data[0] & 4;
	o.keep_comment   = data[0] & 8;
	o.grouping_limit        = data[1] & 0x0f;          // admin accepts any int >= 0
	o.groups_grouping_limit = (data[1] >> 4) & 0x0f;
	static const int lens[4] = { 65000, 2048, 128, 16 };  // query_digests_max_query_length
	o.max_query_length = lens[data[2] & 3];
	return o;
}
