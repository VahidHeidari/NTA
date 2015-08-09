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

#include "Packet.h"

#include "Utilities.h"

constexpr size_t Packet::MTU;
constexpr size_t Packet::TCP_PAYLOAD_SIZE;
constexpr size_t Packet::UDP_PAYLOAD_SIZE;

Packet::Packet()
{
	memset(this, 0, sizeof(Packet));
}

Packet::Packet(ether_header* eth, iphdr* ip, tcphdr* tcp)
: payload_length(0)
{
	memcpy(&frame.tcp_pkt.ethernet, eth, sizeof(ether_header));
	memcpy(&frame.tcp_pkt.ip, ip, sizeof(iphdr));
	memcpy(&frame.tcp_pkt.tcp, tcp, sizeof(tcphdr));
	memset(frame.tcp_pkt.payload, 0, sizeof(frame.tcp_pkt.payload));
	set_type(PacketType::TCP);
}

Packet::~Packet()
{
}

uint16_t Packet::checksum16_tcp_tcp()
{
	uint32_t sum = 0;
	uint16_t tcp_len = htons(frame.tcp_pkt.ip.tot_len) - (frame.tcp_pkt.ip.ihl << 2);

	// TCP psudo header
	sum += (uint16_t)frame.tcp_pkt.ip.saddr; 
	sum += (uint16_t)(frame.tcp_pkt.ip.saddr >> 16);
	sum += (uint16_t)frame.tcp_pkt.ip.daddr;
	sum += (uint16_t)(frame.tcp_pkt.ip.daddr >> 16);
	sum += htons(IPPROTO_TCP);
	sum += htons(tcp_len);

	// TCP header
	frame.tcp_pkt.tcp.check = 0;
	uint16_t* tcp_header = (uint16_t*)&frame.tcp_pkt.tcp;
	while (tcp_len > 1) {
		sum += *tcp_header++;
		tcp_len -= 2;
	}

	if (tcp_len > 0) {
		sum += *tcp_header & 0x00FF;
	}

	sum = (uint16_t)sum + (uint16_t)(sum >> 16);
	sum += sum >> 16;
	sum = ~sum;
	frame.tcp_pkt.tcp.check = sum;
	return frame.tcp_pkt.tcp.check;
}

uint16_t Packet::checksum16_tcp_ip()
{
	frame.tcp_pkt.ip.check = 0;
	frame.tcp_pkt.ip.check = Utilities::checksum16((uint8_t*)&frame.tcp_pkt.ip, frame.tcp_pkt.ip.ihl << 2);
	return frame.tcp_pkt.ip.check;
}

