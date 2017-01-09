/**
 * NTA (Network Traffic Analyser) is contains simple tools for analysing
 * netwrok traffic.
 *
 * Copyright (C) 2015  Vahid Heidari (DeltaCode)
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "Utilities.h"

namespace Utilities
{

uint16_t checksum16(const uint8_t* buff, size_t len)
{
	uint32_t sum = 0;

	while (len > 1) {
		sum += *(reinterpret_cast<const uint16_t*>(buff));
		buff += 2;
		len -= 2;
	}

	// Odd number of octets. Add zeros at end of octet.
	if (len > 0)
		sum += *buff;

	sum = static_cast<uint16_t>(sum) + static_cast<uint16_t>(sum >> 16);
	sum += sum >> 16;
	return ~sum;
}

uint16_t checksum16_tcp(const iphdr* ip, tcphdr* tcp)
{
	uint32_t sum = 0;
	uint16_t tcp_len = htons(ip->tot_len) - (ip->ihl << 2);

	// TCP psudo header
	sum += static_cast<uint16_t>(ip->saddr); 
	sum += static_cast<uint16_t>(ip->saddr >> 16);
	sum += static_cast<uint16_t>(ip->daddr);
	sum += static_cast<uint16_t>(ip->daddr >> 16);
	sum += htons(IPPROTO_TCP);
	sum += htons(tcp_len);

	// TCP header
	tcp->check = 0;
	const uint16_t* tcp_header = reinterpret_cast<const uint16_t*>(tcp);
	while (tcp_len > 1) {
		sum += *tcp_header++;
		tcp_len -= 2;
	}

	if (tcp_len > 0)
		sum += *reinterpret_cast<const uint8_t*>(tcp_header);

	sum = static_cast<uint16_t>(sum) + static_cast<uint16_t>(sum >> 16);
	sum += sum >> 16;
	sum = ~sum;
	tcp->check = sum;
	return sum;
}

uint16_t checksum16_ipv6_tcp(const ip6_hdr* ip, tcphdr* tcp)
{
	uint32_t sum = 0;
	uint16_t tcp_len = htons(ip->ip6_plen);

	// TCP psudo header
	sum += static_cast<uint16_t>(ip->ip6_src.s6_addr16[0]); 
	sum += static_cast<uint16_t>(ip->ip6_src.s6_addr16[1]); 
	sum += static_cast<uint16_t>(ip->ip6_src.s6_addr16[2]); 
	sum += static_cast<uint16_t>(ip->ip6_src.s6_addr16[3]); 
	sum += static_cast<uint16_t>(ip->ip6_src.s6_addr16[4]); 
	sum += static_cast<uint16_t>(ip->ip6_src.s6_addr16[5]); 
	sum += static_cast<uint16_t>(ip->ip6_src.s6_addr16[6]); 
	sum += static_cast<uint16_t>(ip->ip6_src.s6_addr16[7]); 

	sum += static_cast<uint16_t>(ip->ip6_dst.s6_addr16[0]);
	sum += static_cast<uint16_t>(ip->ip6_dst.s6_addr16[1]);
	sum += static_cast<uint16_t>(ip->ip6_dst.s6_addr16[2]);
	sum += static_cast<uint16_t>(ip->ip6_dst.s6_addr16[3]);
	sum += static_cast<uint16_t>(ip->ip6_dst.s6_addr16[4]);
	sum += static_cast<uint16_t>(ip->ip6_dst.s6_addr16[5]);
	sum += static_cast<uint16_t>(ip->ip6_dst.s6_addr16[6]);
	sum += static_cast<uint16_t>(ip->ip6_dst.s6_addr16[7]);
	sum += htons(IPPROTO_TCP);
	sum += htons(tcp_len);

	// TCP header
	tcp->check = 0;
	const uint16_t* tcp_header = reinterpret_cast<const uint16_t*>(tcp);
	while (tcp_len > 1) {
		sum += *tcp_header++;
		tcp_len -= 2;
	}

	if (tcp_len > 0)
		sum += *reinterpret_cast<const uint8_t*>(tcp_header);

	sum = static_cast<uint16_t>(sum) + static_cast<uint16_t>(sum >> 16);
	sum += sum >> 16;
	sum = ~sum;
	tcp->check = sum;
	return sum;
}

}

