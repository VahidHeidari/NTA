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

#include "TcpSession.h"

#include "Dumper.h"
#include "Packet.h"

using namespace Dumper;

void TcpSession::send_finish_sequence(Packet& src_packet, Packet& dst_packet, timeval& timestamp)
{
	uint32_t src_seq = src_packet.get_tcp_seq();
	uint32_t dst_seq = src_packet.get_tcp_ack_seq();

	src_packet.reset_tcp_payload();
	dst_packet.reset_tcp_payload();

	// Finising sequence.
	// Packet no. 1.
	// Send FIN flag and ACK flag.
	timestamp.tv_usec += 10;
	src_packet.reset_tcp_flags();
	src_packet.set_tcp_flag_ack();
	src_packet.set_tcp_flag_fin();
	src_packet.set_tcp_seq(src_seq);
	src_packet.set_tcp_ack_seq(dst_seq);
	src_packet.checksum16_tcp();
	dump_packet(src_packet, timestamp);
	++src_seq;

	// Packet no. 2.
	// Send ACK flag.
	timestamp.tv_usec += 10;
	dst_packet.reset_tcp_flags();
	dst_packet.set_tcp_flag_ack();
	dst_packet.set_tcp_seq(dst_seq);
	dst_packet.set_tcp_ack_seq(src_seq);
	dst_packet.checksum16_tcp();
	dump_packet(dst_packet, timestamp);

	// Packet no. 3.
	// Send FIN flag and ACK flag. Destination connection closing. Source closed.
	timestamp.tv_usec += 10;
	dst_packet.reset_tcp_flags();
	dst_packet.set_tcp_flag_ack();
	dst_packet.set_tcp_flag_fin();
	dst_packet.set_tcp_seq(dst_seq);
	dst_packet.set_tcp_ack_seq(src_seq);
	dst_packet.checksum16_tcp();
	dump_packet(dst_packet, timestamp);
	++dst_seq;

	// Packet no. 4.
	// Send ACK flag.
	timestamp.tv_usec += 10;
	src_packet.reset_tcp_flags();
	src_packet.set_tcp_flag_ack();
	src_packet.set_tcp_seq(src_seq);
	src_packet.set_tcp_ack_seq(dst_seq);
	src_packet.checksum16_tcp();
	dump_packet(src_packet, timestamp);
}

void TcpSession::send_finish_sequence(Packet& src_packet, Packet& dst_packet, timeval& timestamp, uint32_t& src_seq, uint32_t& dst_seq)
{
	src_packet.set_tcp_seq(src_seq);
	src_packet.set_tcp_ack_seq(dst_seq);
	send_finish_sequence(src_packet, dst_packet, timestamp);
}

void TcpSession::send_start_sequence(Packet& src_packet, Packet& dst_packet, timeval& timestamp, uint32_t& src_seq, uint32_t& dst_seq)
{
	// Packet no. 1
	// Send SYN.
	src_packet.reset_tcp_flags();
	src_packet.set_tcp_flag_syn();
	src_packet.set_tcp_seq(src_seq);
	src_packet.checksum16_tcp();
	dump_packet(src_packet, timestamp);

	// Packet no. 2
	// Send SYN ACK.
	timestamp.tv_usec += 10;
	++src_seq;
	dst_packet.set_tcp_flag_syn();
	dst_packet.set_tcp_flag_ack();
	dst_packet.set_tcp_seq(dst_seq);
	dst_packet.set_tcp_ack_seq(src_seq);
	dst_packet.checksum16_tcp();
	dump_packet(dst_packet, timestamp);

	// Packet no. 3
	// Send ACK and establish connection.
	timestamp.tv_usec += 10;
	++dst_seq;
	src_packet.reset_tcp_flags();
	src_packet.set_tcp_flag_ack();
	src_packet.set_tcp_seq(src_seq);
	src_packet.set_tcp_ack_seq(dst_seq);
	src_packet.checksum16_tcp();
	dump_packet(src_packet, timestamp);
}

void TcpSession::send_ack(Packet& packet, struct timeval& timestamp, uint32_t&seq, uint32_t&ack)
{
	timestamp.tv_usec += 10;
	packet.reset_tcp_payload();
	packet.reset_tcp_flags();
	packet.set_tcp_flag_ack();
	packet.set_tcp_seq(seq);
	packet.set_tcp_ack_seq(ack);
	packet.checksum16_tcp();
	dump_packet(packet, timestamp);
}

