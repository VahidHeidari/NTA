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
#include "Utilities.h"

using namespace std;
using namespace Dumper;

static constexpr int FIXED_LAYER3_SIZE = sizeof(ether_header) + sizeof(iphdr);

void init_packet_src(Packet& packet)
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

void init_packet_src_ipv6(Packet& packet)
{
	// Ethernet header initialization
	packet.frame.ipv6_tcp_pkt.ethernet.ether_dhost[0] = 0xFE;
	packet.frame.ipv6_tcp_pkt.ethernet.ether_dhost[1] = 0xFF;
	packet.frame.ipv6_tcp_pkt.ethernet.ether_dhost[2] = 0x20;
	packet.frame.ipv6_tcp_pkt.ethernet.ether_dhost[3] = 0x00;
	packet.frame.ipv6_tcp_pkt.ethernet.ether_dhost[4] = 0x10;
	packet.frame.ipv6_tcp_pkt.ethernet.ether_dhost[5] = 0x00;

	packet.frame.ipv6_tcp_pkt.ethernet.ether_shost[0] = 0x00;
	packet.frame.ipv6_tcp_pkt.ethernet.ether_shost[1] = 0x00;
	packet.frame.ipv6_tcp_pkt.ethernet.ether_shost[2] = 0x10;
	packet.frame.ipv6_tcp_pkt.ethernet.ether_shost[3] = 0x00;
	packet.frame.ipv6_tcp_pkt.ethernet.ether_shost[4] = 0x00;
	packet.frame.ipv6_tcp_pkt.ethernet.ether_shost[5] = 0x00;

	packet.frame.ipv6_tcp_pkt.ethernet.ether_type = htons(ETHERTYPE_IPV6);

	// IPv6 header initialization
	packet.frame.ipv6_tcp_pkt.ip.ip6_src.s6_addr32[0] = 0xad434803;
	packet.frame.ipv6_tcp_pkt.ip.ip6_src.s6_addr32[1] = 0xad434803;
	packet.frame.ipv6_tcp_pkt.ip.ip6_src.s6_addr32[2] = 0xad434803;
	packet.frame.ipv6_tcp_pkt.ip.ip6_src.s6_addr32[3] = 0xad434803;

	packet.frame.ipv6_tcp_pkt.ip.ip6_dst.s6_addr32[0] = 0x18487703;
	packet.frame.ipv6_tcp_pkt.ip.ip6_dst.s6_addr32[1] = 0xad434803;
	packet.frame.ipv6_tcp_pkt.ip.ip6_dst.s6_addr32[2] = 0xad438838;
	packet.frame.ipv6_tcp_pkt.ip.ip6_dst.s6_addr32[3] = 0x00004803;

	packet.frame.ipv6_tcp_pkt.ip.ip6_vfc = 6 << 4;
	packet.frame.ipv6_tcp_pkt.ip.ip6_plen = htons(20);
	packet.frame.ipv6_tcp_pkt.ip.ip6_nxt = IPPROTO_TCP;

	// TCP header initialization
	packet.frame.ipv6_tcp_pkt.tcp.source = htons(0x0d2c);
	packet.frame.ipv6_tcp_pkt.tcp.dest = htons(0x0050);
	packet.frame.ipv6_tcp_pkt.tcp.doff = sizeof(tcphdr) / 4; // 32 bit (4 byte) word offset.
	packet.frame.ipv6_tcp_pkt.tcp.window = htons(8760);
}

void dump_corrupted_tcp()
{
	// Create packet.
	Packet packet;
	timeval tv = {1, 0};
	init_packet_src(packet);

	int packet_size = sizeof(ether_header) + sizeof(iphdr) + (sizeof(tcphdr) / 2);

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
}

int get_layer4_size(int packet_size)
{
	return packet_size - FIXED_LAYER3_SIZE;
}

void dump_corrupted_ip()
{
	// Create packet.
	Packet packet;
	timeval tv = {1, 0};
	init_packet_src(packet);
	packet.frame.tcp_pkt.ip.protocol = 0;

	int packet_size = 80;
	int layer4_size = get_layer4_size(packet_size);

	packet.frame.tcp_pkt.ip.ihl = 5;
	packet.frame.tcp_pkt.ip.frag_off = htons(IP_MF | 20 >> 3);
	packet.frame.tcp_pkt.ip.tot_len = htons(layer4_size + sizeof(iphdr));

	// Calculate CRC.
	if ((packet.frame.tcp_pkt.ip.ihl << 2) < static_cast<int>(sizeof(iphdr)))
		Utilities::checksum16(reinterpret_cast<uint8_t*>(&packet.frame.tcp_pkt.ip), sizeof(iphdr));
	else
		packet.checksum16_tcp_ip();

	++tv.tv_sec;
	// Dump corrupted IP packet #1
	dump_packet(packet.frame.raw, packet_size, tv);

	packet_size = 80;
	layer4_size = get_layer4_size(packet_size);
	packet.frame.tcp_pkt.ip.ihl = 5;
	packet.frame.tcp_pkt.ip.frag_off = htons(IP_MF | 24 >> 3);
	packet.frame.tcp_pkt.ip.tot_len = htons(layer4_size + sizeof(iphdr));

	// Calculate CRC.
	if ((packet.frame.tcp_pkt.ip.ihl << 2) < static_cast<int>(sizeof(iphdr)))
		Utilities::checksum16(reinterpret_cast<uint8_t*>(&packet.frame.tcp_pkt.ip), sizeof(iphdr));
	else
		packet.checksum16_tcp_ip();
	++tv.tv_sec;
	// Dump corrupted IP packet #2
	dump_packet(packet.frame.raw, packet_size, tv);

	packet_size = 1500;
	layer4_size = get_layer4_size(packet_size);
	packet.frame.tcp_pkt.ip.ihl = 5;
	packet.frame.tcp_pkt.ip.frag_off = htons(IP_MF | 0 >> 3);
	packet.frame.tcp_pkt.ip.tot_len = htons(layer4_size + sizeof(iphdr));

	// Calculate CRC.
	if ((packet.frame.tcp_pkt.ip.ihl << 2) < static_cast<int>(sizeof(iphdr)))
		Utilities::checksum16(reinterpret_cast<uint8_t*>(&packet.frame.tcp_pkt.ip), sizeof(iphdr));
	else
		packet.checksum16_tcp_ip();
	++tv.tv_sec;
	// Dump corrupted IP packet #3
	dump_packet(packet.frame.raw, packet_size, tv);

	packet_size = 34;
	packet.frame.tcp_pkt.ip.ihl = 5;
	layer4_size = 80;
	packet.frame.tcp_pkt.ip.frag_off = htons(layer4_size >> 3);
	packet.frame.tcp_pkt.ip.tot_len = htons(packet_size + 14);

	// Calculate CRC.
	if ((packet.frame.tcp_pkt.ip.ihl << 2) < static_cast<int>(sizeof(iphdr)))
		Utilities::checksum16(reinterpret_cast<uint8_t*>(&packet.frame.tcp_pkt.ip), sizeof(iphdr));
	else
		packet.checksum16_tcp_ip();
	++tv.tv_sec;
	// Dump corrupted IP packet #4
	dump_packet(packet.frame.raw, packet_size, tv);
}

void dump_corrupted_ipv6()
{
	// Create packet.
	Packet packet;
	timeval tv = {1, 0};
	init_packet_src_ipv6(packet);

	int packet_size = sizeof(ether_header) + sizeof(ip6_hdr) + sizeof(tcphdr);
	Utilities::checksum16_ipv6_tcp(&packet.frame.ipv6_tcp_pkt.ip, &packet.frame.ipv6_tcp_pkt.tcp);

	// Dump corrupted IP packet #1
	dump_packet(packet.frame.raw, packet_size, tv);
}

void print_help()
{
	cerr << "    T  : Generate TCP corrupted packets." << endl;
	cerr << "    I  : Generate IP corrupted packets." << endl;
	cerr << "    I6 : Generate IPv6 corrupted packets." << endl;
}

int main(int argc, char** argv)
{
	if (argc < 2) {
		cerr << "Command required!" << endl;
		print_help();
		return 1;
	}

	if (!init_dumper("packet.pcap")) {
		cerr << "Could not open output file!" << endl;
		return 1;
	}

	if (argv[1][0] == 'T')
		dump_corrupted_tcp();
	else if (argv[1][0] == 'I' && argv[1][1] == '\0')
		dump_corrupted_ip();
	else if (argv[1][0] == 'I' && argv[1][1] == '6')
		dump_corrupted_ipv6();
	else {
		cerr << "Unkown command!" << endl;
		print_help();
		close_dumper();
		return 1;
	}

	if (!close_dumper()) {
		cerr << "Could not close output file!" << endl;
		return 1;
	}

	return 0;
}

