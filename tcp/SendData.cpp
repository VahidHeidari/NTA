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

#include "SendData.h"

#include "Dumper.h"
#include "Packet.h"
#include "TcpSession.h"

using namespace Dumper;

void packet_1600()
{
	const char* payload_data = (char*)"GET /index.html HTTP 1.1\r\n";
	char payload[Packet::TCP_PAYLOAD_SIZE] = { 0 };
	memset(payload, 0xaa, sizeof(payload));
	memcpy(payload, payload_data, strlen(payload_data));

	Packet p;

	p.frame.tcp_pkt.ethernet.ether_shost[0] = 0xFE;
	p.frame.tcp_pkt.ethernet.ether_shost[1] = 0xFF;
	p.frame.tcp_pkt.ethernet.ether_shost[2] = 0x20;
	p.frame.tcp_pkt.ethernet.ether_shost[3] = 0x00;
	p.frame.tcp_pkt.ethernet.ether_shost[4] = 0x10;
	p.frame.tcp_pkt.ethernet.ether_shost[5] = 0x00;
	p.frame.tcp_pkt.ethernet.ether_dhost[0] = 0x00;
	p.frame.tcp_pkt.ethernet.ether_dhost[1] = 0x00;
	p.frame.tcp_pkt.ethernet.ether_dhost[2] = 0x10;
	p.frame.tcp_pkt.ethernet.ether_dhost[3] = 0x00;
	p.frame.tcp_pkt.ethernet.ether_dhost[4] = 0x00;
	p.frame.tcp_pkt.ethernet.ether_dhost[5] = 0x00;
	p.frame.tcp_pkt.ethernet.ether_type = htons(ETHERTYPE_IP);

	p.frame.tcp_pkt.ip.version = 4;
	p.frame.tcp_pkt.ip.ihl = 5;
	p.frame.tcp_pkt.ip.tot_len = htons(sizeof(tcphdr) + sizeof(iphdr));//sizeof(packet.payload));
	p.frame.tcp_pkt.ip.ttl = 128;
	p.frame.tcp_pkt.ip.protocol = IPPROTO_TCP;
	p.frame.tcp_pkt.ip.daddr = htonl(0x91fea0ed);
	p.frame.tcp_pkt.ip.saddr = htonl(0x41d0e4df);

	p.frame.tcp_pkt.tcp.dest = htons(0x0d2c);
	p.frame.tcp_pkt.tcp.source = htons(0x0050);
	p.frame.tcp_pkt.tcp.doff = sizeof(tcphdr) / 4; // 32 bit (4 byte) word offset.
	p.frame.tcp_pkt.tcp.window = htons(8760);

	p.set_tcp_payload((const uint8_t*)payload, sizeof(payload)); 
	p.checksum16_tcp();

	timeval tv = { 0, 0 };
	dump_packet(p, tv);
}

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

static void init_packet_dst(Packet& packet)
{
	packet.set_type(Packet::TCP);

	// Ethernet header initialization
	packet.frame.tcp_pkt.ethernet.ether_shost[0] = 0xFE;
	packet.frame.tcp_pkt.ethernet.ether_shost[1] = 0xFF;
	packet.frame.tcp_pkt.ethernet.ether_shost[2] = 0x20;
	packet.frame.tcp_pkt.ethernet.ether_shost[3] = 0x00;
	packet.frame.tcp_pkt.ethernet.ether_shost[4] = 0x10;
	packet.frame.tcp_pkt.ethernet.ether_shost[5] = 0x00;

	packet.frame.tcp_pkt.ethernet.ether_dhost[0] = 0x00;
	packet.frame.tcp_pkt.ethernet.ether_dhost[1] = 0x00;
	packet.frame.tcp_pkt.ethernet.ether_dhost[2] = 0x10;
	packet.frame.tcp_pkt.ethernet.ether_dhost[3] = 0x00;
	packet.frame.tcp_pkt.ethernet.ether_dhost[4] = 0x00;
	packet.frame.tcp_pkt.ethernet.ether_dhost[5] = 0x00;

	packet.frame.tcp_pkt.ethernet.ether_type = htons(ETHERTYPE_IP);
	
	// IP header initialization
	packet.frame.tcp_pkt.ip.version = 4;
	packet.frame.tcp_pkt.ip.ihl = 5;
	packet.frame.tcp_pkt.ip.tot_len = htons(sizeof(tcphdr) + sizeof(iphdr));//sizeof(packet.payload));
	packet.frame.tcp_pkt.ip.ttl = 128;
	packet.frame.tcp_pkt.ip.protocol = IPPROTO_TCP;
	packet.frame.tcp_pkt.ip.daddr = htonl(0x91fea0ed);
	packet.frame.tcp_pkt.ip.saddr = htonl(0x41d0e4df);

	// TCP header initialization
	packet.frame.tcp_pkt.tcp.dest = htons(0x0d2c);
	packet.frame.tcp_pkt.tcp.source = htons(0x0050);
	packet.frame.tcp_pkt.tcp.doff = sizeof(tcphdr) / 4; // 32 bit (4 byte) word offset.
	packet.frame.tcp_pkt.tcp.window = htons(8760);
}

void send()
{
	char* payload_data;

	timeval timestamp = { 0, 0 };
	Packet src_packet, dst_packet;
	uint32_t src_seq, dst_seq;
	init_packet_src(src_packet);
	init_packet_dst(dst_packet);
	src_seq = 1;
	dst_seq = 80;

	TcpSession::send_start_sequence(src_packet, dst_packet, timestamp, src_seq, dst_seq);

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
	TcpSession::send_data((uint8_t*)payload_data, strlen(payload_data), src_packet, timestamp, src_seq, dst_seq);

	// Packet no. 5
	TcpSession::send_ack(dst_packet, timestamp, dst_seq, src_seq);

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
	dst_packet.reset_tcp_flags();
	dst_packet.set_tcp_flag_ack();
	dst_packet.set_tcp_seq(dst_seq);
	dst_packet.set_tcp_ack_seq(src_seq);
	dst_packet.set_tcp_payload((const uint8_t*)payload_data, strlen(payload_data));
	dst_packet.checksum16_tcp();
	dump_packet(dst_packet, timestamp);
	dst_seq += strlen(payload_data);

	// Packet no. 7
	TcpSession::send_ack(src_packet, timestamp, src_seq, dst_seq);

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
		"\t\t<p>This is test paragraph!</p>\n";
	timestamp.tv_usec += 10;
	dst_packet.reset_tcp_flags();
	dst_packet.set_tcp_flag_ack();
	dst_packet.set_tcp_flag_psh();
	dst_packet.set_tcp_seq(dst_seq);
	dst_packet.set_tcp_ack_seq(src_seq);
	dst_packet.set_tcp_payload((const uint8_t*)payload_data, strlen(payload_data));
	dst_packet.checksum16_tcp();
	dump_packet(dst_packet, timestamp);
	dst_seq += strlen(payload_data);

	// Packet no. 9
	payload_data = (char*)"\t<table>"
		"\t\t<tr><td>No.</td><td>Name</td><td>Account</td></tr>\n"
		"\t\t<tr><td>1</td><td>Smith</td><td>11233</td></tr>\n"
		"\t\t<tr><td>2</td><td>Jhonson</td><td>33410</td></tr>\n"
		"\t\t<tr><td>3</td><td>Jackson</td><td>5566400</td></tr>\n"
		"\t</table>\n";
	timestamp.tv_usec += 10;
	dst_packet.reset_tcp_flags();
	dst_packet.set_tcp_flag_ack();
	dst_packet.set_tcp_flag_psh();
	dst_packet.set_tcp_seq(dst_seq);
	dst_packet.set_tcp_ack_seq(src_seq);
	dst_packet.set_tcp_payload((const uint8_t*)payload_data, strlen(payload_data));
	dst_packet.checksum16_tcp();
	dump_packet(dst_packet, timestamp);
	dst_seq += strlen(payload_data);
	
	// Packet no. 10
	payload_data = (char*)"\t<p>This is a test pragraph.</p>\n"
		"\t<p>This is a test pragraph.</p>\n"
		"\t<p>This is a test pragraph.</p>\n"
		"\t<p>This is a test pragraph.</p>\n"
		"\t<p>This is a test pragraph.</p>\n"
		"\t<p>This is a test pragraph.</p>\n";
	timestamp.tv_usec += 10;
	dst_packet.reset_tcp_flags();
	dst_packet.set_tcp_flag_ack();
	dst_packet.set_tcp_seq(dst_seq);
	dst_packet.set_tcp_ack_seq(src_seq);
	dst_packet.set_tcp_payload((const uint8_t*)payload_data, strlen(payload_data));
	dst_packet.checksum16_tcp();
	dump_packet(dst_packet, timestamp);
	dst_seq += strlen(payload_data);

	// Packet no. 11
	TcpSession::send_ack(src_packet, timestamp, src_seq, dst_seq);

	// Packet no. 12
	payload_data = (char*)"\t<p>This is a test pragraph.</p>\n"
		"\t<p>This is a test paragraph.</p>\n"
		"\t<p>This is a test paragraph.</p>\n"
		"\t<p>This is a test paragraph.</p>\n"
		"\t<p>This is a test paragraph.</p>\n"
		"\t<p>This is a test paragraph.</p>\n";
	timestamp.tv_usec += 10;
	dst_packet.reset_tcp_flags();
	dst_packet.set_tcp_flag_ack();
	dst_packet.set_tcp_seq(dst_seq);
	dst_packet.set_tcp_ack_seq(src_seq);
	dst_packet.set_tcp_payload((const uint8_t*)payload_data, strlen(payload_data));
	dst_packet.checksum16_tcp();
	dump_packet(dst_packet, timestamp);
	dst_seq += strlen(payload_data);

	// Packet no. 13
	payload_data = (char*)"\t</body>\n"
		"</html>\n";
	timestamp.tv_usec += 10;
	dst_packet.reset_tcp_flags();
	dst_packet.set_tcp_flag_ack();
	dst_packet.set_tcp_seq(dst_seq);
	dst_packet.set_tcp_ack_seq(src_seq);
	dst_packet.set_tcp_payload((const uint8_t*)payload_data, strlen(payload_data));
	dst_packet.checksum16_tcp();
	dump_packet(dst_packet, timestamp);
	dst_seq += strlen(payload_data);

	// Packet no. 14
	// Last ACK packet.
	TcpSession::send_ack(src_packet, timestamp, src_seq, dst_seq);

	TcpSession::send_finish_sequence(src_packet, dst_packet, timestamp);
}

void send_out_of_order()
{
	char* payload_data;

	timeval timestamp = { 0, 0 };
	Packet src_packet, dst_packet;
	uint32_t src_seq, dst_seq;
	init_packet_src(src_packet);
	init_packet_dst(dst_packet);
	src_seq = 1;
	dst_seq = 80;

	TcpSession::send_start_sequence(src_packet, dst_packet, timestamp, src_seq, dst_seq);

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
	src_packet.reset_tcp_flags();
	src_packet.set_tcp_flag_ack();
	src_packet.set_tcp_seq(src_seq);
	src_packet.set_tcp_ack_seq(dst_seq);
	src_packet.set_tcp_payload((const uint8_t*)payload_data, strlen(payload_data));
	src_packet.checksum16_tcp();
	dump_packet(src_packet, timestamp);
	src_seq += strlen(payload_data);

	// Packet no. 5
	TcpSession::send_ack(dst_packet, timestamp, dst_seq, src_seq);

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
	dst_packet.reset_tcp_flags();
	dst_packet.set_tcp_flag_ack();
	dst_packet.set_tcp_seq(dst_seq);
	dst_packet.set_tcp_ack_seq(src_seq);
	dst_packet.set_tcp_payload((const uint8_t*)payload_data, strlen(payload_data));
	dst_packet.checksum16_tcp();
	dump_packet(dst_packet, timestamp);
	dst_seq += strlen(payload_data);

	// Packet no. 7
	TcpSession::send_ack(src_packet, timestamp, src_seq, dst_seq);

	// OUT OF ORDER DATA
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
		"\t\t<p>This is test paragraph!</p>\n";

	const char* payload_data_9 = (char*)"\t<table>"
		"\t\t<tr><td>No.</td><td>Name</td><td>Account</td></tr>\n"
		"\t\t<tr><td>1</td><td>Smith</td><td>11233</td></tr>\n"
		"\t\t<tr><td>2</td><td>Jhonson</td><td>33410</td></tr>\n"
		"\t\t<tr><td>3</td><td>Jackson</td><td>5566400</td></tr>\n"
		"\t</table>\n";

	const char* payload_data_10 = (char*)"\t<p>This is a lost segment.</p>\n"
		"\t<p>This is a lost segment.</p>\n"
		"\t<p>This is a lost segment.</p>\n"
		"\t<p>This is a lost segment.</p>\n"
		"\t<p>This is a lost segment.</p>\n"
		"\t<p>This is a lost segment.</p>\n";
	int dst_seq_8  = dst_seq;
	int dst_seq_9  = dst_seq + strlen(payload_data);
	int dst_seq_10 = dst_seq_9 + strlen(payload_data_9);
	int dst_seq_correction = dst_seq_10 + strlen(payload_data_10);

	// Packet no. 10
	// payload_data_10
	timestamp.tv_usec += 10;
	dst_packet.reset_tcp_flags();
	dst_packet.set_tcp_flag_ack();
	dst_packet.set_tcp_seq(dst_seq_10);
	dst_packet.set_tcp_ack_seq(src_seq);
	dst_packet.set_tcp_payload((const uint8_t*)payload_data_10, strlen(payload_data_10));
	dst_packet.checksum16_tcp();
	dump_packet(dst_packet, timestamp);

	// Packet no. 9
	// payload_data_9
	timestamp.tv_usec += 10;
	dst_packet.reset_tcp_flags();
	dst_packet.set_tcp_flag_ack();
	dst_packet.set_tcp_flag_psh();
	dst_packet.set_tcp_seq(dst_seq_9);
	dst_packet.set_tcp_ack_seq(src_seq);
	dst_packet.set_tcp_payload((const uint8_t*)payload_data_9, strlen(payload_data_9));
	dst_packet.checksum16_tcp();
	dump_packet(dst_packet, timestamp);

	// Packet no. 8
	// payload_data
	timestamp.tv_usec += 10;
	dst_packet.reset_tcp_flags();
	dst_packet.set_tcp_flag_ack();
	dst_packet.set_tcp_flag_psh();
	dst_packet.set_tcp_seq(dst_seq_8);
	dst_packet.set_tcp_ack_seq(src_seq);
	dst_packet.set_tcp_payload((const uint8_t*)payload_data, strlen(payload_data));
	dst_packet.checksum16_tcp();
	dump_packet(dst_packet, timestamp);

	// Correct sequence number.
	dst_seq = dst_seq_correction;

	// Packet no. 11
	timestamp.tv_usec += 10;
	src_packet.reset_tcp_payload();
	src_packet.reset_tcp_flags();
	src_packet.set_tcp_flag_ack();
	src_packet.set_tcp_seq(src_seq);
	src_packet.set_tcp_ack_seq(dst_seq);
	src_packet.checksum16_tcp();
	dump_packet(src_packet, timestamp);
	
	// Packet no. 12
	payload_data = (char*)"\t<p>This is a test pragraph.</p>\n"
		"\t<p>This is a test pragraph.</p>\n"
		"\t<p>This is a test pragraph.</p>\n"
		"\t<p>This is a test pragraph.</p>\n"
		"\t<p>This is a test pragraph.</p>\n"
		"\t<p>This is a test pragraph.</p>\n";
	timestamp.tv_usec += 10;
	dst_packet.reset_tcp_flags();
	dst_packet.set_tcp_flag_ack();
	dst_packet.set_tcp_seq(dst_seq);
	dst_packet.set_tcp_ack_seq(src_seq);
	dst_packet.set_tcp_payload((const uint8_t*)payload_data, strlen(payload_data));
	dst_packet.checksum16_tcp();
	dump_packet(dst_packet, timestamp);
	dst_seq += strlen(payload_data);

	// Packet no. 13
	payload_data = (char*)"\t</body>\n"
		"</html>\n";
	timestamp.tv_usec += 10;
	dst_packet.reset_tcp_flags();
	dst_packet.set_tcp_flag_ack();
	dst_packet.set_tcp_seq(dst_seq);
	dst_packet.set_tcp_ack_seq(src_seq);
	dst_packet.set_tcp_payload((const uint8_t*)payload_data, strlen(payload_data));
	dst_packet.checksum16_tcp();
	dump_packet(dst_packet, timestamp);
	dst_seq += strlen(payload_data);

	// Packet no. 14
	// Last ACK packet.
	timestamp.tv_usec += 10;
	src_packet.reset_tcp_payload();
	src_packet.reset_tcp_flags();
	src_packet.set_tcp_flag_ack();
	src_packet.set_tcp_seq(src_seq);
	src_packet.set_tcp_ack_seq(dst_seq);
	src_packet.checksum16_tcp();
	dump_packet(src_packet, timestamp);

	TcpSession::send_finish_sequence(src_packet, dst_packet, timestamp);
}

void send_out_of_order_lost()
{
	char* payload_data;

	timeval timestamp = { 0, 0 };
	Packet src_packet, dst_packet;
	uint32_t src_seq, dst_seq;
	init_packet_src(src_packet);
	init_packet_dst(dst_packet);
	src_seq = 1;
	dst_seq = 80;

	TcpSession::send_start_sequence(src_packet, dst_packet, timestamp, src_seq, dst_seq);

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
	src_packet.reset_tcp_flags();
	src_packet.set_tcp_flag_ack();
	src_packet.set_tcp_seq(src_seq);
	src_packet.set_tcp_ack_seq(dst_seq);
	src_packet.set_tcp_payload((const uint8_t*)payload_data, strlen(payload_data));
	src_packet.checksum16_tcp();
	dump_packet(src_packet, timestamp);
	src_seq += strlen(payload_data);

	// Packet no. 5
	timestamp.tv_usec += 10;
	dst_packet.reset_tcp_payload();
	dst_packet.reset_tcp_flags();
	dst_packet.set_tcp_flag_ack();
	dst_packet.set_tcp_seq(dst_seq);
	dst_packet.set_tcp_ack_seq(src_seq);
	dst_packet.checksum16_tcp();
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
	dst_packet.reset_tcp_flags();
	dst_packet.set_tcp_flag_ack();
	dst_packet.set_tcp_seq(dst_seq);
	dst_packet.set_tcp_ack_seq(src_seq);
	dst_packet.set_tcp_payload((const uint8_t*)payload_data, strlen(payload_data));
	dst_packet.checksum16_tcp();
	dump_packet(dst_packet, timestamp);
	dst_seq += strlen(payload_data);

	// Packet no. 7
	timestamp.tv_usec += 10;
	src_packet.reset_tcp_payload();
	src_packet.reset_tcp_flags();
	src_packet.set_tcp_flag_ack();
	src_packet.set_tcp_seq(src_seq);
	src_packet.set_tcp_ack_seq(dst_seq);
	src_packet.checksum16_tcp();
	dump_packet(src_packet, timestamp);

	// OUT OF ORDER DATA
	payload_data = (char*)"\t<body>\n"
		"\t\t<h4>This is test html page!</h4>\n"
		"\t\t<p>This is test paragraph!</p>\n"
		"\t\t<p>This is test paragraph!</p>\n"
		"\t\t<p>This is test paragraph!</p>\n"
		"\t\t<p>This is test paragraph!</p>\n"
		"\t\t<p>This is test paragraph!</p>\n";

	const char* payload_data_9 = (char*)"\t<table>"
		"\t\t<tr><td>No.</td><td>Name</td><td>Account</td></tr>\n"
		"\t\t<tr><td>1</td><td>Smith</td><td>11233</td></tr>\n"
		"\t\t<tr><td>2</td><td>Jhonson</td><td>33410</td></tr>\n"
		"\t\t<tr><td>3</td><td>Jackson</td><td>5566400</td></tr>\n"
		"\t</table>\n";

	const char* payload_data_10 = (char*)"\t<p>This is a lost segment.</p>\n"
		"\t<p>This is a lost segment.</p>\n"
		"\t<p>This is a lost segment.</p>\n"
		"\t<p>This is a lost segment.</p>\n"
		"\t<p>This is a lost segment.</p>\n"
		"\t<p>This is a lost segment.</p>\n";

	const char* payload_data_11 = (char*)"\t\t<p>This is test paragraph!</p>\n"
		"\t\t<p>This is test paragraph!</p>\n"
		"\t\t<p>This is test paragraph!</p>\n"
		"\t\t<p>This is test paragraph!</p>\n"
		"\t\t<p>This is test paragraph!</p>\n"
		"\t\t<p>This is test paragraph!</p>\n";

	int dst_seq_8  = dst_seq;
	int dst_seq_9  = dst_seq    + strlen(payload_data);
	int dst_seq_10 = dst_seq_9  + strlen(payload_data_9);
	int dst_seq_11 = dst_seq_10 + strlen(payload_data_10);
	int dst_seq_correction = dst_seq_11 + strlen(payload_data_11);

	// Packet no. 8
	// payload_data
	timestamp.tv_usec += 10;
	dst_packet.reset_tcp_flags();
	dst_packet.set_tcp_flag_ack();
	dst_packet.set_tcp_flag_psh();
	dst_packet.set_tcp_seq(dst_seq_8);
	dst_packet.set_tcp_ack_seq(src_seq);
	dst_packet.set_tcp_payload((const uint8_t*)payload_data, strlen(payload_data));
	dst_packet.checksum16_tcp();
	dump_packet(dst_packet, timestamp);

	// Packet no. 9
	// payload_data_9
	timestamp.tv_usec += 10;
	dst_packet.reset_tcp_flags();
	dst_packet.set_tcp_flag_ack();
	dst_packet.set_tcp_flag_psh();
	dst_packet.set_tcp_seq(dst_seq_9);
	dst_packet.set_tcp_ack_seq(src_seq);
	dst_packet.set_tcp_payload((const uint8_t*)payload_data_9, strlen(payload_data_9));
	dst_packet.checksum16_tcp();
	dump_packet(dst_packet, timestamp);

	// Packet no. 10
	// payload_data_10
	timestamp.tv_usec += 10;
	dst_packet.reset_tcp_flags();
	dst_packet.set_tcp_flag_ack();
	dst_packet.set_tcp_seq(dst_seq_10);
	dst_packet.set_tcp_ack_seq(src_seq);
	dst_packet.set_tcp_payload((const uint8_t*)payload_data_10, strlen(payload_data_10));
	dst_packet.checksum16_tcp();
	dump_packet(dst_packet, timestamp);

	// Packet no. 11
	// payload_data_11
	timestamp.tv_usec += 10;
	dst_packet.reset_tcp_flags();
	dst_packet.set_tcp_flag_ack();
	dst_packet.set_tcp_seq(dst_seq_11);
	dst_packet.set_tcp_ack_seq(src_seq);
	dst_packet.set_tcp_payload((const uint8_t*)payload_data_11, strlen(payload_data_11));
	dst_packet.checksum16_tcp();
	dump_packet(dst_packet, timestamp);

	// Correct sequence number.
	dst_seq = dst_seq_correction;

	// Packet no. 12
	timestamp.tv_usec += 10;
	src_packet.reset_tcp_payload();
	src_packet.reset_tcp_flags();
	src_packet.set_tcp_flag_ack();
	src_packet.set_tcp_seq(src_seq);
	src_packet.set_tcp_ack_seq(dst_seq);
	src_packet.checksum16_tcp();
	dump_packet(src_packet, timestamp);
	
	// Packet no. 13
	payload_data = (char*)"\t<div><p>BLOCK 13</p>\n"
		"\t<p>This is a test pragraph.</p>\n"
		"\t<p>This is a test pragraph.</p>\n"
		"\t<p>This is a test pragraph.</p>\n"
		"\t<p>This is a test pragraph.</p>\n"
		"\t<p>END BLOCK 13.</p><div>\n";

	timestamp.tv_usec += 10;
	dst_packet.reset_tcp_flags();
	dst_packet.set_tcp_flag_ack();
	dst_packet.set_tcp_seq(dst_seq);
	dst_packet.set_tcp_ack_seq(src_seq);
	dst_packet.set_tcp_payload((const uint8_t*)payload_data, strlen(payload_data));
	dst_packet.checksum16_tcp();
	dump_packet(dst_packet, timestamp);
	dst_seq += strlen(payload_data);

	// Packet no. 14
	payload_data = (char*)"\t</body>\n"
		"</html>\n";
	timestamp.tv_usec += 10;
	dst_packet.reset_tcp_flags();
	dst_packet.set_tcp_flag_ack();
	dst_packet.set_tcp_seq(dst_seq);
	dst_packet.set_tcp_ack_seq(src_seq);
	dst_packet.set_tcp_payload((const uint8_t*)payload_data, strlen(payload_data));
	dst_packet.checksum16_tcp();
	dump_packet(dst_packet, timestamp);
	dst_seq += strlen(payload_data);

	// Packet no. 15
	// Last ACK packet.
	TcpSession::send_ack(src_packet, timestamp, src_seq, dst_seq);

	TcpSession::send_finish_sequence(src_packet, dst_packet, timestamp);
}

void send_test()
{
	static const char* data[] = {
		"",
		"1",
		"2",
		"3",
		"4",
		"5",
		"6"
	};

	Packet src_pkt;
	Packet dst_pkt;

	init_packet_src(src_pkt);
	init_packet_dst(dst_pkt);

	uint32_t src_seq = 1;
	uint32_t dst_seq = 0;

	timeval tv;

	TcpSession::send_start_sequence(src_pkt, dst_pkt, tv, src_seq, dst_seq);

	src_seq = 2; TcpSession::send_data<false>((uint8_t*)&data[1][0], strlen(data[1]), src_pkt, tv, src_seq, dst_seq);
	src_seq = 6; TcpSession::send_data<false>((uint8_t*)&data[5][0], strlen(data[5]), src_pkt, tv, src_seq, dst_seq);
	src_seq = 5; TcpSession::send_data<false>((uint8_t*)&data[4][0], strlen(data[4]), src_pkt, tv, src_seq, dst_seq);
	src_seq = 4; TcpSession::send_data<false>((uint8_t*)&data[3][0], strlen(data[3]), src_pkt, tv, src_seq, dst_seq);
	src_seq = 3; TcpSession::send_data<false>((uint8_t*)&data[2][0], strlen(data[2]), src_pkt, tv, src_seq, dst_seq);
	src_seq = 7; TcpSession::send_data<false>((uint8_t*)&data[6][0], strlen(data[6]), src_pkt, tv, src_seq, dst_seq);

	src_seq = 8;
	TcpSession::send_ack(dst_pkt, tv, dst_seq, src_seq);
	TcpSession::send_finish_sequence(src_pkt, dst_pkt, tv, src_seq, dst_seq);
}

