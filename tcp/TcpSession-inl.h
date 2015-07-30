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

#ifndef TCP_SESSION_H_
#error This file must not be used directly!

template <bool advance_seq>
void TcpSession::send_data(const uint8_t* data, size_t size, Packet& packet, struct timeval& timestamp, uint32_t& seq, uint32_t& ack)
{
	timestamp.tv_usec += 10;
	packet.reset_tcp_flags();
	packet.set_tcp_flag_ack();
	packet.set_tcp_seq(seq);
	packet.set_tcp_ack_seq(ack);
	packet.set_tcp_payload(data, size); 
	packet.checksum16_tcp();
	dump_packet(packet, timestamp);

	if (advance_seq)
		seq += size;
}

#endif

