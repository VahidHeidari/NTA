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
#include <iomanip>
#include <cstring>

#include "Dumper.h"
#include "Packet.h"
#include "TcpSession.h"

using namespace std;
using namespace Dumper;

char* payload_data;

void init_packet_src(Packet& packet)
{
	// Ethernet header initialization
	packet.ethernet.ether_dhost[0] = 0xFE;
	packet.ethernet.ether_dhost[1] = 0xFF;
	packet.ethernet.ether_dhost[2] = 0x20;
	packet.ethernet.ether_dhost[3] = 0x00;
	packet.ethernet.ether_dhost[4] = 0x10;
	packet.ethernet.ether_dhost[5] = 0x00;

	packet.ethernet.ether_shost[0] = 0x00;
	packet.ethernet.ether_shost[1] = 0x00;
	packet.ethernet.ether_shost[2] = 0x10;
	packet.ethernet.ether_shost[3] = 0x00;
	packet.ethernet.ether_shost[4] = 0x00;
	packet.ethernet.ether_shost[5] = 0x00;

	packet.ethernet.ether_type = htons(ETHERTYPE_IP);
	
	// IP header initialization
	packet.ip.version = 4;
	packet.ip.ihl = 5;
	packet.ip.tot_len = htons(sizeof(tcphdr) + sizeof(iphdr));
	packet.ip.ttl = 128;
	packet.ip.protocol = IPPROTO_TCP;
	packet.ip.saddr = htonl(0x91fea0ed);
	packet.ip.daddr = htonl(0x41d0e4df);

	// TCP header initialization
	packet.tcp.source = htons(0x0d2c);
	packet.tcp.dest = htons(0x0050);
	packet.tcp.doff = sizeof(tcphdr) / 4; // 32 bit (4 byte) word offset.
	packet.tcp.window = htons(8760);
}

void init_packet_dst(Packet& packet)
{
	// Ethernet header initialization
	packet.ethernet.ether_shost[0] = 0xFE;
	packet.ethernet.ether_shost[1] = 0xFF;
	packet.ethernet.ether_shost[2] = 0x20;
	packet.ethernet.ether_shost[3] = 0x00;
	packet.ethernet.ether_shost[4] = 0x10;
	packet.ethernet.ether_shost[5] = 0x00;

	packet.ethernet.ether_dhost[0] = 0x00;
	packet.ethernet.ether_dhost[1] = 0x00;
	packet.ethernet.ether_dhost[2] = 0x10;
	packet.ethernet.ether_dhost[3] = 0x00;
	packet.ethernet.ether_dhost[4] = 0x00;
	packet.ethernet.ether_dhost[5] = 0x00;

	packet.ethernet.ether_type = htons(ETHERTYPE_IP);
	
	// IP header initialization
	packet.ip.version = 4;
	packet.ip.ihl = 5;
	packet.ip.tot_len = htons(sizeof(tcphdr) + sizeof(iphdr));//sizeof(packet.payload));
	packet.ip.ttl = 128;
	packet.ip.protocol = IPPROTO_TCP;
	packet.ip.daddr = htonl(0x91fea0ed);
	packet.ip.saddr = htonl(0x41d0e4df);

	// TCP header initialization
	packet.tcp.dest = htons(0x0d2c);
	packet.tcp.source = htons(0x0050);
	packet.tcp.doff = sizeof(tcphdr) / 4; // 32 bit (4 byte) word offset.
	packet.tcp.window = htons(8760);
}

int main()
{
	cout << endl;
	cout << "---------------------------------" << endl;
	cout << "  This is TCP packet generator." << endl;
	cout << "---------------------------------" << endl << endl;

	if (!init_dumper("./TCP-GEN.pcap")) {
		cout << "Could not initialize dumper!" << endl;
		return 1;
	}

	timeval timestamp = { 0, 0 };
	Packet src_packet, dst_packet;
	uint32_t src_seq, dst_seq;
	init_packet_src(src_packet);
	init_packet_dst(dst_packet);
	src_seq = 1;
	dst_seq = 80;

	// Packet no. 1
	// Send SYN.
	src_packet.set_flag_syn();
	src_packet.set_seq(src_seq);
	src_packet.checksum16();
	dump_packet(src_packet, timestamp);

	// Packet no. 2
	// Send SYN ACK.
	timestamp.tv_usec += 10;
	++src_seq;
	dst_packet.set_flag_syn();
	dst_packet.set_flag_ack();
	dst_packet.set_seq(dst_seq);
	dst_packet.set_ack_seq(src_seq);
	dst_packet.checksum16();
	dump_packet(dst_packet, timestamp);

	// Packet no. 3
	// Send ACK and establish connection.
	timestamp.tv_usec += 10;
	++dst_seq;
	src_packet.reset_flags();
	src_packet.set_flag_ack();
	src_packet.set_seq(src_seq);
	src_packet.set_ack_seq(dst_seq);
	src_packet.checksum16();
	dump_packet(src_packet, timestamp);

	// Packet no. 4
	payload_data = (char*)"GET /index.html HTTP 1.1\r\n"
		"Host: mail.yahoo.com\r\n"
		"User-agent: Mozilla/5.0\r\n"
		"Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9/plain;q=0.8,image/png,image/jpeg,image/gif;q=0.2,*/*;q=0.1\r\n"
		"Accept-Language: en-us,en;q=0.5\r\n"
		"Accept-Encoding: gzip,deflate\r\n"
		"Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"
		"Keep-Alive: 300\r\n"
		"Connection: keep-alive\r\n"
		"Referer: http://www.yahoo.com\r\n"
		"\r\n";
	timestamp.tv_usec += 10;
	src_packet.reset_flags();
	src_packet.set_flag_ack();
	src_packet.set_seq(src_seq);
	src_packet.set_ack_seq(dst_seq);
	src_packet.set_payload((const uint8_t*)payload_data, strlen(payload_data));
	src_packet.checksum16();
	dump_packet(src_packet, timestamp);
	src_seq += strlen(payload_data);

	// Packet no. 5
	timestamp.tv_usec += 10;
	dst_packet.reset_payload();
	dst_packet.reset_flags();
	dst_packet.set_flag_ack();
	dst_packet.set_seq(dst_seq);
	dst_packet.set_ack_seq(src_seq);
	dst_packet.checksum16();
	dump_packet(dst_packet, timestamp);

	// Packet no. 6
	payload_data = (char*)"HTTP/1.1 200 OK\r\n"
		"Date: Thu, 13 May 2004 10:17:12 GMT\r\n"
		"Server: Apache\r\n"
		"Last-Modified: Tue, 20 Apr 2004 13:17:00 GMT\r\n"
		"ETag: \"9a01a-4696-7e354b00\"\r\n"
		"Accept-Ranges: bytes\r\n"
		"Content-Length: 18070\r\n"
		"Keep-Alive: timeout=15, max=100\r\n"
		"Connection: Keep-Alive\r\n"
		"Content-Type: text/html; charset=ISO-8859-1\r\n"
		"\r\n"
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
		"<!DOCTYPE html\n"
		"\tPUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\n"
		"\t\"DTD/xhtml1-strict.dtd\">\n"
		"<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\" lang=\"en\">\n"
		"\t<head>\n"
		"\t\t<title>Ethereal: Download</title>\n"
		"\t\t<style type=\"text/css\" media=\"all\">.@import url(\"mm/css/ethereal-3-0.css\");</style>\n"
		"\t</head>\n";
	timestamp.tv_usec += 10;
	dst_packet.reset_flags();
	dst_packet.set_flag_ack();
	dst_packet.set_seq(dst_seq);
	dst_packet.set_ack_seq(src_seq);
	dst_packet.set_payload((const uint8_t*)payload_data, strlen(payload_data));
	dst_packet.checksum16();
	dump_packet(dst_packet, timestamp);
	dst_seq += strlen(payload_data);

	// Packet no. 7
	timestamp.tv_usec += 10;
	src_packet.reset_payload();
	src_packet.reset_flags();
	src_packet.set_flag_ack();
	src_packet.set_seq(src_seq);
	src_packet.set_ack_seq(dst_seq);
	src_packet.checksum16();
	dump_packet(src_packet, timestamp);

	// Packet no. 8
	payload_data = (char*)"\t<body>\n"
		"\t\t<h4>This is test html page!</h4>\n"
		"\t\t<p>This is test paragraph!</p>\n"
		"\t\t<p>This is test paragraph!</p>\n"
		"\t\t<p>This is test paragraph!</p>\n"
		"\t\t<p>This is test paragraph!</p>\n"
		"\t\t<p>This is test paragraph!</p>\n"
		"\t\t<p>This is test paragraph!</p>\n"
		"\t\t<p>This is test paragraph!</p>\n"
		"\t\t<p>This is test paragraph!</p>\n"
		"\t\t<p>This is test paragraph!</p>\n"
		"\t\t<p>This is test paragraph!</p>\n"
		"\t\t<p>This is test paragraph!</p>\n"
		"\t</body>";
	timestamp.tv_usec += 10;
	dst_packet.reset_flags();
	dst_packet.set_flag_ack();
	dst_packet.set_flag_psh();
	dst_packet.set_seq(dst_seq);
	dst_packet.set_ack_seq(src_seq);
	dst_packet.set_payload((const uint8_t*)payload_data, strlen(payload_data));
	dst_packet.checksum16();
	dump_packet(dst_packet, timestamp);
	dst_seq += strlen(payload_data);

	// Packet no. 9
	// Last ACK packet.
	timestamp.tv_usec += 10;
	src_packet.reset_payload();
	src_packet.reset_flags();
	src_packet.set_flag_ack();
	src_packet.set_seq(src_seq);
	src_packet.set_ack_seq(dst_seq);
	src_packet.checksum16();
	dump_packet(src_packet, timestamp);

	TcpSession::send_finish_sequence(src_packet, dst_packet, timestamp);

	close_dumper();

	return 0;
}

