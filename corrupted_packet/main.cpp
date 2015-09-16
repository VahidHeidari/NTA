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

#include <iostream>

#include "Packet.h"
#include "Dumper.h"

using namespace std;
using namespace Dumper;

static void init_packet_src(Packet& packet)
{
	packet.set_type(Packet::TCP);

	// Ethernet header initialization
	packet.frame.tcp_pkt.ethernet.ether_dhost[0] = 0xFE;
	packet.frame.tcp_pkt.ethernet.ether_dhost[1] = 0xFF;
	packet.frame.tcp_pkt.ethernet.ether_dhost[2] = 0x20;
	packet.frame.tcp_pkt.ethernet.ether_dhost[3] = 0x00;
	packet.frame.tcp_pkt.ethernet.ether_dhost[4] = 0x10;
	packet.frame.tcp_pkt.ethernet.ether_dhost[5] = 0x00;

	packet.frame.tcp_pkt.ethernet.ether_shost[0] = 0x00;
	packet.frame.tcp_pkt.ethernet.ether_shost[1] = 0x00;
	packet.frame.tcp_pkt.ethernet.ether_shost[2] = 0x10;
	packet.frame.tcp_pkt.ethernet.ether_shost[3] = 0x00;
	packet.frame.tcp_pkt.ethernet.ether_shost[4] = 0x00;
	packet.frame.tcp_pkt.ethernet.ether_shost[5] = 0x00;

	packet.frame.tcp_pkt.ethernet.ether_type = htons(ETHERTYPE_IP);
	
	// IP header initialization
	packet.frame.tcp_pkt.ip.version = 4;
	packet.frame.tcp_pkt.ip.ihl = 5;
	packet.frame.tcp_pkt.ip.tot_len = htons((sizeof(tcphdr) / 2) + sizeof(iphdr));
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

int main()
{
	if (!init_dumper("packet.pcap")) {
		cerr << "Could not open output file!" << endl;
		return 1;
	}

	int packet_size = sizeof(ether_header) + sizeof(iphdr) + (sizeof(tcphdr) / 2);
	// Create packet.
	Packet packet;
	timeval tv = {1, 0};
	init_packet_src(packet);
	packet.checksum16_tcp();
	// Dump corrupted packet #1.
	dump_packet(packet.frame.raw, packet_size, tv);

	packet.frame.tcp_pkt.ip.tot_len = htons(sizeof(tcphdr) + sizeof(iphdr));
	packet.checksum16_tcp();
	++tv.tv_sec;
	// Dump corrupted packet #2.
	dump_packet(packet.frame.raw, packet_size, tv);

	packet.frame.tcp_pkt.ip.tot_len = htons(sizeof(tcphdr) + sizeof(iphdr) + 10);
	packet.checksum16_tcp();
	++tv.tv_sec;
	// Dump corrupted packet #3.
	dump_packet(packet.frame.raw, packet_size, tv);

	if (!close_dumper()) {
		cerr << "Could not close output file!" << endl;
		return 1;
	}

	return 0;
}

