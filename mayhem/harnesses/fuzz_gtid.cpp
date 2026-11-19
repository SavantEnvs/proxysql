// libFuzzer target: ProxySQL's GTID parsers (lib/proxysql_gtid.cpp) — MySQL `uuid:N[-M][:...]` and
// MariaDB `domain-server-seq` GTIDs and GTID sets, as they arrive from backends in OK-packet
// session tracking (SESSION_TRACK_GTIDS / last_gtid) and the binlog-reader stream, and from the
// GTID-routing query annotation. Calls the entry points MySQL_Session, MySQL_Query_Processor and
// GTID_Server_Data use, then round-trips a parsed set through GTID_Set.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <map>
#include <string>
#include <vector>
#include "proxysql_gtid.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	char* s = (char*)malloc(size + 1);
	memcpy(s, data, size);
	s[size] = 0;

	ParsedGTID g;
	parse_gtid(s, &g);
	parse_gtid(s, size, &g);

	char uuid[64];  // MySQL_Session.cpp passes a char[64]
	uint64_t trxid = 0;
	parse_gtid_for_routing(s, uuid, sizeof(uuid), &trxid);
	parse_gtid_set_for_routing(s, uuid, sizeof(uuid), &trxid);

	TrxId_Interval iv(0, 0);
	TrxId_Interval::parse(s, &iv);

	std::map<std::string, std::vector<TrxId_Interval>> set;
	if (parse_gtid_set(s, size, &set)) {
		GTID_Set gs;
		for (auto& e : set)
			for (auto& i : e.second) gs.add(e.first, i);
		std::string out = gs.to_string();
		std::string disp = gs.to_display_string();
		(void)out; (void)disp;
	}
	free(s);
	return 0;
}
