/**
 * HttpGen is a HTTP sample traffic generator.
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

#include <cstring>
#include <iostream>

#include "Dumper.h"
#include "HttpContent.h"
#include "Packet.h"
#include "TcpSession.h"

using namespace Dumper;
using namespace HttpContent;
using namespace std;

static constexpr const char* OUTPUT_FILE_NAME = "./http-pipelining.pcap";

static Packet src_packet;
static Packet dst_packet;

static void generate_conversations()
{
	unsigned src_seq = 10;
	unsigned dst_seq = 30;
	timeval curr_time = { 0, 0 };

	TcpSession::send_start_sequence(src_packet, dst_packet, curr_time, src_seq, dst_seq);

	// Requests
	TcpSession::send_data(reinterpret_cast<const uint8_t*>(get_request(0)), strlen(get_request(0)), src_packet, curr_time, src_seq, dst_seq);
	TcpSession::send_data(reinterpret_cast<const uint8_t*>(get_request(1)), strlen(get_request(1)), src_packet, curr_time, src_seq, dst_seq);
	TcpSession::send_data(reinterpret_cast<const uint8_t*>(get_request(2)), strlen(get_request(2)), src_packet, curr_time, src_seq, dst_seq);

	// Responses
	TcpSession::send_data(reinterpret_cast<const uint8_t*>(get_response(0)), strlen(get_response(0)), dst_packet, curr_time, dst_seq, src_seq);
	TcpSession::send_data(reinterpret_cast<const uint8_t*>(get_response(1)), strlen(get_response(1)), dst_packet, curr_time, dst_seq, src_seq);
	TcpSession::send_data(reinterpret_cast<const uint8_t*>(get_response(2)), strlen(get_response(2)), dst_packet, curr_time, dst_seq, src_seq);

	src_packet.reset_tcp_payload();
	dst_packet.reset_tcp_payload();
	TcpSession::send_finish_sequence(src_packet, dst_packet, curr_time, src_seq, dst_seq);
}

static Packet get_src_packet()
{
	Packet packet;

	packet.set_type(Packet::TCP);

	// Ethernet header initialization
	packet.set_src_mac(0x66, 0x1a, 0x8c, 0xc0, 0xe6, 0x6d);
	packet.set_dst_mac(0xbb, 0xde, 0x67, 0x50, 0x22, 0xe5);
	packet.frame.tcp_pkt.ethernet.ether_type = htons(ETHERTYPE_IP);
	
	// IP header initialization
	packet.frame.tcp_pkt.ip.version = 4;
	packet.frame.tcp_pkt.ip.ihl = 5;
	packet.frame.tcp_pkt.ip.tot_len = htons(sizeof(tcphdr) + sizeof(iphdr));
	packet.frame.tcp_pkt.ip.ttl = 128;
	packet.frame.tcp_pkt.ip.protocol = IPPROTO_TCP;
	packet.frame.tcp_pkt.ip.saddr = htonl(0xdd6e8d41);
	packet.frame.tcp_pkt.ip.daddr = htonl(0xc76ae0b5);

	// TCP header initialization
	packet.frame.tcp_pkt.tcp.source = htons(0xc248);
	packet.frame.tcp_pkt.tcp.dest = htons(0x0050);
	packet.frame.tcp_pkt.tcp.doff = sizeof(tcphdr) / 4; // 32 bit (4 byte) word offset.
	packet.frame.tcp_pkt.tcp.window = htons(8760);

	return packet;
}

static Packet get_dst_packet()
{
	Packet packet;

	packet.set_type(Packet::TCP);

	// Ethernet header initialization
	packet.set_src_mac(0xbb, 0xde, 0x67, 0x50, 0x22, 0xe5);
	packet.set_dst_mac(0x66, 0x1a, 0x8c, 0xc0, 0xe6, 0x6d);
	packet.frame.tcp_pkt.ethernet.ether_type = htons(ETHERTYPE_IP);
	
	// IP header initialization
	packet.frame.tcp_pkt.ip.version = 4;
	packet.frame.tcp_pkt.ip.ihl = 5;
	packet.frame.tcp_pkt.ip.tot_len = htons(sizeof(tcphdr) + sizeof(iphdr));
	packet.frame.tcp_pkt.ip.ttl = 128;
	packet.frame.tcp_pkt.ip.protocol = IPPROTO_TCP;
	packet.frame.tcp_pkt.ip.saddr = htonl(0xc76ae0b5);
	packet.frame.tcp_pkt.ip.daddr = htonl(0xdd6e8d41);

	// TCP header initialization
	packet.frame.tcp_pkt.tcp.source = htons(0x0050);
	packet.frame.tcp_pkt.tcp.dest = htons(0xc248);
	packet.frame.tcp_pkt.tcp.doff = sizeof(tcphdr) / 4; // 32 bit (4 byte) word offset.
	packet.frame.tcp_pkt.tcp.window = htons(8760);

	return packet;
}

void generate_pipelining_connection()
{
	if (!init_dumper(OUTPUT_FILE_NAME)) {
		cout << "Could not initialize dumper!" << endl;
		return;
	}

	src_packet = get_src_packet();
	dst_packet = get_dst_packet();

	generate_conversations();

	cout << "Sample traffic is created in '" << OUTPUT_FILE_NAME << "' file!" << endl;
	close_dumper();
}

