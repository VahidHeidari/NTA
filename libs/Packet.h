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

#ifndef PACKET_H_
#define PACKET_H_

#include <algorithm>
#include <cstring>
#include <cstdint>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>

class Packet {
public:
	static constexpr size_t MTU = 1600;		// Max Transmit Unit
	static constexpr size_t TCP_PAYLOAD_SIZE = MTU - sizeof(ether_header) - sizeof(iphdr) - sizeof(tcphdr);
	static constexpr size_t UDP_PAYLOAD_SIZE = MTU - sizeof(ether_header) - sizeof(iphdr) - sizeof(udphdr);

	enum TcpFlags {
		TCP_FLAG_FIN = 0x01,
		TCP_FLAG_SYN = 0x02,
		TCP_FLAG_RST = 0x04,
		TCP_FLAG_PSH = 0x08,
		TCP_FLAG_ACK = 0x10,
	};

	enum PacketType {
		TCP = 0,
		UDP = 1,
		RAW = 2,

		NUM,
	};

	Packet();
	Packet(ether_header* eth, iphdr* ip, tcphdr* tcp);
	~Packet();

	// Ethernet properties.
	void set_tcp_ether_dhost(ether_addr& dhost) { memcpy(frame.tcp_pkt.ethernet.ether_dhost, dhost.ether_addr_octet, sizeof(dhost)); }
	u_int8_t* get_tcp_ether_dhost() { return frame.tcp_pkt.ethernet.ether_dhost; }

	void set_tcp_ether_shost(ether_addr& shost) { memcpy(frame.tcp_pkt.ethernet.ether_shost, shost.ether_addr_octet, sizeof(shost)); }
	u_int8_t* get_tcp_ether_shost() { return frame.tcp_pkt.ethernet.ether_shost; }

	void set_tcp_ether_type (u_int16_t type) { frame.tcp_pkt.ethernet.ether_type = type; }
	u_int16_t get_tcp_ether_type () const { return frame.tcp_pkt.ethernet.ether_type; }

	void set_str_mac(uint8_t addr[ETH_ALEN]) { memcpy(frame.tcp_pkt.ethernet.ether_shost, addr, ETH_ALEN); }
	void set_src_mac(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e, uint8_t f) {
		auto& eth = frame.tcp_pkt.ethernet;
		eth.ether_shost[0] = a; eth.ether_shost[1] = b; eth.ether_shost[2] = c;
		eth.ether_shost[3] = d; eth.ether_shost[4] = e; eth.ether_shost[5] = f;
	}

	void set_dst_mac(uint8_t addr[ETH_ALEN]) { memcpy(frame.tcp_pkt.ethernet.ether_dhost, addr, ETH_ALEN); }
	void set_dst_mac(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e, uint8_t f) {
		auto& eth = frame.tcp_pkt.ethernet;
		eth.ether_dhost[0] = a; eth.ether_dhost[1] = b; eth.ether_dhost[2] = c;
		eth.ether_dhost[3] = d; eth.ether_dhost[4] = e; eth.ether_dhost[5] = f;
	}

	// TCP properties.
	void set_tcp_source(uint16_t src_ip) { frame.tcp_pkt.tcp.source = src_ip; }
	uint16_t get_tcp_source() const { return frame.tcp_pkt.tcp.source; }

	void set_tcp_dest(uint16_t dst_ip) { frame.tcp_pkt.tcp.dest = dst_ip; }
	uint16_t get_tcp_dest() const { return frame.tcp_pkt.tcp.dest; }

	void reset_tcp_flags() { frame.tcp_pkt.tcp.seq = frame.tcp_pkt.tcp.ack_seq = frame.tcp_pkt.tcp.fin = frame.tcp_pkt.tcp.syn = frame.tcp_pkt.tcp.rst = frame.tcp_pkt.tcp.ack = frame.tcp_pkt.tcp.psh = frame.tcp_pkt.tcp.urg = 0; }
	void   set_tcp_flags() { frame.tcp_pkt.tcp.seq = frame.tcp_pkt.tcp.ack_seq = frame.tcp_pkt.tcp.fin = frame.tcp_pkt.tcp.syn = frame.tcp_pkt.tcp.rst = frame.tcp_pkt.tcp.ack = frame.tcp_pkt.tcp.psh = frame.tcp_pkt.tcp.urg = 1; }

	void set_tcp_seq(uint32_t seq) { frame.tcp_pkt.tcp.seq = htonl(seq); }
	uint32_t get_tcp_seq() const { return ntohl(frame.tcp_pkt.tcp.seq); }

	void set_tcp_ack_seq(uint32_t ack) { frame.tcp_pkt.tcp.ack_seq = htonl(ack); }
	uint32_t get_tcp_ack_seq() const { return ntohl(frame.tcp_pkt.tcp.ack_seq); }

	void set_tcp_flag_fin() { frame.tcp_pkt.tcp.fin = 1; }
	void reset_tcp_flag_fin() { frame.tcp_pkt.tcp.fin = 0; }
	bool get_tcp_flag_fin() const { return frame.tcp_pkt.tcp.fin == 1; }

	void set_tcp_flag_syn() { frame.tcp_pkt.tcp.syn = 1; }
	void reset_tcp_flag_syn() { frame.tcp_pkt.tcp.syn = 0; }
	bool get_tcp_flag_syn() const { return frame.tcp_pkt.tcp.syn == 1; }

	void set_tcp_flag_rst() { frame.tcp_pkt.tcp.rst = 1; }
	void reset_tcp_flag_rst() { frame.tcp_pkt.tcp.rst = 0; }
	bool set_tcp_flag_rst() const { return frame.tcp_pkt.tcp.rst == 1; }

	void set_tcp_flag_psh() { frame.tcp_pkt.tcp.psh = 1; }
	void reset_tcp_flag_psh() { frame.tcp_pkt.tcp.psh = 0; }
	bool set_tcp_flag_psh() const { return frame.tcp_pkt.tcp.psh == 1; }

	void set_tcp_flag_ack() { frame.tcp_pkt.tcp.ack = 1; }
	void reset_tcp_flag_ack() { frame.tcp_pkt.tcp.ack = 0; }
	bool set_tcp_ack() const { return frame.tcp_pkt.tcp.ack == 1; }

	void set_tcp_flag_urg() { frame.tcp_pkt.tcp.urg = 1; }
	void reset_tcp_flag_urg() { frame.tcp_pkt.tcp.urg = 0; }
	bool set_tcp_flag_urg() const { return frame.tcp_pkt.tcp.urg == 1; }

	void set_tcp_window(uint16_t window) { frame.tcp_pkt.tcp.window = htonl(window); }
	uint16_t get_tcp_window() const { return ntohl(frame.tcp_pkt.tcp.window); }

	void set_tcp_check(uint16_t check) { frame.tcp_pkt.tcp.check = check; }
	uint16_t checksum16_tcp_tcp();
	uint16_t get_tcp_check() const { return frame.tcp_pkt.tcp.check; }
	void set_tcp_ip_check(uint16_t check) { frame.tcp_pkt.ip.check = check; }
	uint16_t checksum16_tcp_ip();
	uint16_t get_tcp_ip_check() const { return frame.tcp_pkt.ip.check; } 
	void checksum16_tcp()
	{
		checksum16_tcp_ip();
		checksum16_tcp_tcp();
	}

	void set_tcp_urg_ptr(uint16_t urg) { frame.tcp_pkt.tcp.urg_ptr = urg; }
	uint16_t get_tcp_urg_ptr() const { return frame.tcp_pkt.tcp.urg_ptr; }

	// Payload
	void set_tcp_payload(const uint8_t* data, size_t len)
	{
		len = std::min(len, TCP_PAYLOAD_SIZE);
		memcpy(frame.tcp_pkt.payload, data, len);
		payload_length = len;
		frame.tcp_pkt.ip.tot_len = htons(sizeof(iphdr) + sizeof(tcphdr) + payload_length);
	}
	void reset_tcp_payload() { set_tcp_payload((const uint8_t*)"", 0); }
	size_t get_payload_length() const { return payload_length; }

	// Entire frame
	uint8_t* get_frame() const { return (uint8_t*)&frame.raw; }
	size_t get_tcp_frame_size() const { return sizeof(ether_header) + sizeof(iphdr) + sizeof(tcphdr) + payload_length; }
	size_t get_udp_frame_size() const { return sizeof(ether_header) + sizeof(iphdr) + sizeof(udphdr) + payload_length; }

	/// Packet Type
	bool is_tcp() const { return type == PacketType::TCP; }
	bool is_udp() const { return type == PacketType::UDP; }
	bool is_raw() const { return type == PacketType::RAW; }
	void set_type(PacketType t) { type = t; }

private:
	size_t payload_length;
	PacketType type;

public:
	/// This must be at the end of class only! Don't declare any member below here, please.
	union Frame {
		/// TCP packet
		struct __attribute__ ((__packed__)) Tcp {
			ether_header	ethernet;
			iphdr			ip;
			tcphdr			tcp;
			uint8_t			payload[TCP_PAYLOAD_SIZE];
		} tcp_pkt;

		/// UDP packet
		struct __attribute__ ((__packed__)) Udp {
			ether_header	ethernet;
			iphdr			ip;
			udphdr			udp;
			uint8_t			payload[UDP_PAYLOAD_SIZE];
		} udp_pkt;

		/// Raw packet frame
		uint8_t raw[MTU];
	} frame;
};

#endif		// PACKET_H_

