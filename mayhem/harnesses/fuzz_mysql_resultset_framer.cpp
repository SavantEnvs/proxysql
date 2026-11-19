// libFuzzer target: ProxySQL's MySQL server-response framing (lib/MySQLResultsetFramer.cpp) and the
// OK/ERR/EOF/length-encoded-integer parsers it and MySQLFFTO use (lib/MySQLProtocolUtils.cpp), fed a
// backend byte stream the way MySQLFFTO::process_server_packet does.
// Input: byte 0 = flags (bit0 binary protocol, bit1 CLIENT_DEPRECATE_EOF); rest = MySQL packets,
// each a 3-byte little-endian payload length + 1 sequence byte + payload.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "MySQLProtocolUtils.h"
#include "MySQLResultsetFramer.h"

static void standalone_parsers(const unsigned char* p, size_t n) {
	MySQLOkFields ok;
	mysql_is_ok_header(p, n);
	mysql_parse_ok_payload(p, n, &ok);
	uint16_t w, s;
	mysql_is_eof_payload(p, n);
	mysql_parse_eof_payload(p, n, &w, &s);
	uint16_t err; const char* msg; size_t msg_len;
	if (mysql_parse_err_packet(p, n, &err, &msg, &msg_len) && msg && msg_len) {
		volatile char c = msg[msg_len - 1]; (void)c;  // the message must lie inside the payload
	}
	const unsigned char* q = p; size_t left = n;
	while (left) {
		size_t before = left;
		mysql_read_lenenc_int(q, left);
		if (left >= before) break;
	}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	if (size < 1) return -1;
	const bool binary = data[0] & 1, deprecate_eof = data[0] & 2;
	MySQLResultsetFramer rs;
	rs.begin(binary, deprecate_eof);
	size_t off = 1;
	while (size - off >= 4) {
		size_t n = data[off] | (data[off + 1] << 8) | (data[off + 2] << 16);
		off += 4;
		if (n > size - off) n = size - off;
		// Exact-size heap copy so ASan catches any read past the payload.
		unsigned char* p = (unsigned char*)malloc(n ? n : 1);
		memcpy(p, data + off, n);
		off += n;
		standalone_parsers(p, n);
		if (!rs.active()) rs.begin(binary, deprecate_eof);  // next query's response
		MySQLRSEvent ev = rs.on_payload(p, n);
		(void)ev;
		free(p);
	}
	return 0;
}
