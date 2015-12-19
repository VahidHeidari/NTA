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

#include "Fragmenter.h"

void Fragmenter::init(Packet& packet) const
{
	packet.set_type(Packet::TCP);

	// Ethernet header initialization
	packet.set_src_mac(0xFE, 0xFF, 0x20, 0x00, 0x10, 0x00);
	packet.set_dst_mac(0x00, 0x00, 0x10, 0x00, 0x00, 0x00);
	packet.frame.tcp_pkt.ethernet.ether_type = htons(ETHERTYPE_IP);
	
	// IP header initialization
	packet.frame.tcp_pkt.ip.version = 4;
	packet.frame.tcp_pkt.ip.ihl = 5;
	packet.frame.tcp_pkt.ip.tot_len = htons(sizeof(tcphdr) + sizeof(iphdr));
	packet.frame.tcp_pkt.ip.ttl = 128;
	packet.frame.tcp_pkt.ip.protocol = IPPROTO_TCP;
	packet.frame.tcp_pkt.ip.saddr = htonl(0x91fea0ed);
	packet.frame.tcp_pkt.ip.daddr = htonl(0x41d0e4df);

	// TCP header initialization
	packet.frame.tcp_pkt.tcp.source = htons(0x0d2c);
	packet.frame.tcp_pkt.tcp.dest = htons(0x0050);
	packet.frame.tcp_pkt.tcp.doff = sizeof(tcphdr) / 4; // 32 bit (4 byte) word offset.
	packet.frame.tcp_pkt.tcp.window = htons(8760);
}

