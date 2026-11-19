// libFuzzer target: ProxySQL's PROXY protocol handling (lib/proxy_protocol_info.cpp), the way a
// listener with proxy protocol enabled uses it:
//   - MySQL_Threads_Handler::set_variable("proxy_protocol_networks") validates the configured
//     network list with is_valid_subnet_list() (empty and "*" are accepted without it);
//   - MySQL_Data_Stream::buffer2array() checks the TCP peer against that list with
//     is_client_in_any_subnet() and then parses the first bytes the client sent with
//     parseProxyProtocolHeader().
// Input layout: <client bytes> NUL <proxy_protocol_networks>. The split is at the LAST NUL byte
// (the network list is a C string, so it never holds one); with no NUL the whole input is the
// client bytes and the list is empty.
// Beyond the peer check, the parsed source address (the address ProxySQL then uses as the client
// address) is also matched against the list, to drive the IPv6 half of is_in_network().
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include "proxy_protocol_info.h"

static void match_networks(ProxyProtocolInfo& ppi, const struct sockaddr* sa, const std::string& nets) {
	volatile bool in = ppi.is_client_in_any_subnet(sa, nets.c_str());
	(void)in;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	size_t hdr_len = size;
	std::string nets;
	const uint8_t* nul = (const uint8_t*)memrchr(data, 0, size);
	if (nul) {
		hdr_len = (size_t)(nul - data);
		nets.assign((const char*)nul + 1, size - hdr_len - 1);
	}

	// Configuration gate: set_variable() only stores a list is_valid_subnet_list() accepts
	// (or "" / "*", which never reach is_client_in_any_subnet()).
	ProxyProtocolInfo cfg;
	bool nets_ok = !nets.empty() && nets != "*" && cfg.is_valid_subnet_list(nets.c_str());

	ProxyProtocolInfo ppi;
	if (nets_ok) {
		// The real TCP peer, IPv4 and IPv6.
		struct sockaddr_in p4; memset(&p4, 0, sizeof(p4));
		p4.sin_family = AF_INET; inet_pton(AF_INET, "10.1.2.3", &p4.sin_addr);
		match_networks(ppi, (const struct sockaddr*)&p4, nets);
		struct sockaddr_in6 p6; memset(&p6, 0, sizeof(p6));
		p6.sin6_family = AF_INET6; inet_pton(AF_INET6, "2001:db8::1", &p6.sin6_addr);
		match_networks(ppi, (const struct sockaddr*)&p6, nets);
	}

	char* pkt = (char*)malloc(hdr_len ? hdr_len : 1);
	memcpy(pkt, data, hdr_len);
	if (ppi.parseProxyProtocolHeader(pkt, hdr_len)) {
		ProxyProtocolInfo copy;
		copy.copy(ppi);
		if (nets_ok) {
			struct sockaddr_in s4; memset(&s4, 0, sizeof(s4));
			struct sockaddr_in6 s6; memset(&s6, 0, sizeof(s6));
			if (inet_pton(AF_INET, copy.source_address, &s4.sin_addr) == 1) {
				s4.sin_family = AF_INET;
				match_networks(copy, (const struct sockaddr*)&s4, nets);
			} else if (inet_pton(AF_INET6, copy.source_address, &s6.sin6_addr) == 1) {
				s6.sin6_family = AF_INET6;
				match_networks(copy, (const struct sockaddr*)&s6, nets);
			}
		}
	}
	free(pkt);
	return 0;
}
