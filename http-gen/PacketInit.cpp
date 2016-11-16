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

#include "PacketInit.h"

Packet src_packet;
Packet dst_packet;

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

void intialize_src_and_dst_packets()
{
	src_packet = get_src_packet();
	dst_packet = get_dst_packet();
}

