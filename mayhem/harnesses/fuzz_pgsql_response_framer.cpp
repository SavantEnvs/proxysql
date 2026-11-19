// libFuzzer target: ProxySQL's PostgreSQL backend-message handling — PgSQLResponseFramer
// (lib/PgSQLResponseFramer.cpp), the CommandComplete tag parser (lib/PgSQLCommandComplete.cpp) and
// the ErrorResponse field parser (lib/PgSQLErrorFields.cpp) — fed a backend byte stream the way
// PgSQLFFTO::process_server_message / PgSQL_Connection do.
// Input: byte 0 = flags (bit0 finalize-on-Sync, i.e. extended query); rest = PostgreSQL backend
// messages, each a type byte + 4-byte big-endian length (including itself) + payload.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "PgSQLCommandComplete.h"
#include "PgSQLErrorFields.h"
#include "PgSQLResponseFramer.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	if (size < 1) return -1;
	PgSQLResponseFramer rs;
	rs.on_query_activated(data[0] & 1);
	size_t off = 1;
	while (size - off >= 5) {
		char type = (char)data[off];
		uint32_t l = ((uint32_t)data[off + 1] << 24) | (data[off + 2] << 16) | (data[off + 3] << 8) | data[off + 4];
		off += 5;
		size_t n = l >= 4 ? l - 4 : 0;
		if (n > size - off) n = size - off;
		unsigned char* p = (unsigned char*)malloc(n ? n : 1);
		memcpy(p, data + off, n);
		off += n;
		PgSQLRSEvent ev = rs.on_message(type, p, n);
		if (ev.kind == PgSQLRSEventKind::ReadyForQuery) rs.on_query_activated(data[0] & 1);
		if (type == 'C') parse_pgsql_command_complete(p, n);
		if (type == 'E' || type == 'N') {
			PgSQLErrorResult e = pgsql_parse_error_response(p, n);
			if (e.message && e.message_len) { volatile char c = e.message[e.message_len - 1]; (void)c; }
			if (e.severity && e.severity_len) { volatile char c = e.severity[e.severity_len - 1]; (void)c; }
		}
		free(p);
	}
	return 0;
}
