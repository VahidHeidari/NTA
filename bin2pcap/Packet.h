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

#include <cstring>
#include <cstdint>
#include <algorithm>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>

class Packet {
public:
	static constexpr size_t MAX_SIZEOF_TCP_PAYLOAD = 1600 - sizeof(ether_header) - sizeof(iphdr) - sizeof(tcphdr);

	enum TcpFlags
	{
		TCP_FLAG_FIN		= 0x01,
		TCP_FLAG_SYN		= 0x02,
		TCP_FLAG_RST		= 0x04,
		TCP_FLAG_PSH		= 0x08,
		TCP_FLAG_ACK		= 0x10,
	};

	Packet();
	Packet(ether_header* eth, iphdr* ip, tcphdr* tcp);
	~Packet();

	// Ethernet properties.
	void set_ether_dhost(ether_addr& dhost) { memcpy(ethernet.ether_dhost, dhost.ether_addr_octet, sizeof(dhost)); }
	u_int8_t* get_ether_dhost() { return ethernet.ether_dhost; }

	void set_ether_shost(ether_addr& shost) { memcpy(ethernet.ether_shost, shost.ether_addr_octet, sizeof(shost)); }
	u_int8_t* get_ether_shost() { return ethernet.ether_shost; }

	void set_ether_type (u_int16_t type) { ethernet.ether_type = type; }
	u_int16_t get_ether_type () const { return ethernet.ether_type; }

	// TCP properties.
	void set_source(uint16_t src_ip) { tcp.source = src_ip; }
	uint16_t get_source() const { return tcp.source; }

	void set_dest(uint16_t dst_ip) { tcp.dest = dst_ip; }
	uint16_t get_dest() const { return tcp.dest; }

	void reset_flags() { tcp.seq = tcp.ack_seq = tcp.fin = tcp.syn = tcp.rst = tcp.ack = tcp.psh = tcp.urg = 0; }
	void   set_flags() { tcp.seq = tcp.ack_seq = tcp.fin = tcp.syn = tcp.rst = tcp.ack = tcp.psh = tcp.urg = 1; }

	void set_seq(uint32_t seq) { tcp.seq = htonl(seq); }
	uint32_t get_seq() const { return ntohl(tcp.seq); }

	void set_ack_seq(uint32_t ack) { tcp.ack_seq = htonl(ack); }
	uint32_t get_ack_seq() const { return ntohl(tcp.ack_seq); }

	void set_flag_fin() { tcp.fin = 1; }
	void reset_flag_fin() { tcp.fin = 0; }
	bool get_flag_fin() const { return tcp.fin == 1; }

	void set_flag_syn() { tcp.syn = 1; }
	void reset_flag_syn() { tcp.syn = 0; }
	bool get_flag_syn() const { return tcp.syn == 1; }

	void set_flag_rst() { tcp.rst = 1; }
	void reset_flag_rst() { tcp.rst = 0; }
	bool set_flag_rst() const { return tcp.rst == 1; }

	void set_flag_psh() { tcp.psh = 1; }
	void reset_flag_psh() { tcp.psh = 0; }
	bool set_flag_psh() const { return tcp.psh == 1; }

	void set_flag_ack() { tcp.ack = 1; }
	void reset_flag_ack() { tcp.ack = 0; }
	bool set_ack() const { return tcp.ack == 1; }

	void set_flag_urg() { tcp.urg = 1; }
	void reset_flag_urg() { tcp.urg = 0; }
	bool set_flag_urg() const { return tcp.urg == 1; }

	void set_window(uint16_t window) { tcp.window = htonl(window); }
	uint16_t get_window() const { return ntohl(tcp.window); }

	void set_tcp_check(uint16_t check) { tcp.check = check; }
	uint16_t checksum16_tcp();
	uint16_t get_tcp_check() const { return tcp.check; }
	void set_ip_check(uint16_t check) { ip.check = check; }
	uint16_t checksum16_ip();
	uint16_t get_ip_check() const { return ip.check; } 
	void checksum16()
	{
		checksum16_ip();
		checksum16_tcp();
	}

	void set_urg_ptr(uint16_t urg) { tcp.urg_ptr = urg; }
	uint16_t get_urg_ptr() const { return tcp.urg_ptr; }

	// Payload
	void set_payload(const uint8_t* data, size_t len)
	{
		len = std::min(len, MAX_SIZEOF_TCP_PAYLOAD);
		memcpy(payload, data, len);
		payload_length = len;
		ip.tot_len = htons(sizeof(iphdr) + sizeof(tcphdr) + payload_length);
	}
	void reset_payload() { set_payload((const uint8_t*)"", 0); }
	size_t get_payload_length() const { return payload_length; }

	// Entire frame
	uint8_t* get_frame() const { return (uint8_t*)&ethernet; }
	size_t get_frame_size() const { return sizeof(ether_header) + sizeof(iphdr) + sizeof(tcphdr) + payload_length; }

private:
	size_t payload_length;

public:
	/// This must be at the end of class only! Don't declare any member below here, please.
	struct {
		ether_header	ethernet;
		iphdr			ip;
		tcphdr			tcp;
		uint8_t			payload[MAX_SIZEOF_TCP_PAYLOAD];
	} __attribute__ ((__packed__));
};

#endif

