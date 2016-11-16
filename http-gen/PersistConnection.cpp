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
#include "PacketInit.h"
#include "TcpSession.h"

using namespace Dumper;
using namespace HttpContent;
using namespace std;

static constexpr const char* OUTPUT_FILE_NAME = "./http-persist.pcap";

static void generate_conversations()
{
	unsigned src_seq = 10;
	unsigned dst_seq = 30;
	timeval curr_time = { 0, 0 };

	TcpSession::send_start_sequence(src_packet, dst_packet, curr_time, src_seq, dst_seq);

	// Conversation No. 1
	TcpSession::send_data(reinterpret_cast<const uint8_t*>(get_request(0)), strlen(get_request(0)), src_packet, curr_time, src_seq, dst_seq);
	TcpSession::send_data(reinterpret_cast<const uint8_t*>(get_response(0)), strlen(get_response(0)), dst_packet, curr_time, dst_seq, src_seq);

	// Converstation No. 2
	TcpSession::send_data(reinterpret_cast<const uint8_t*>(get_request(1)), strlen(get_request(1)), src_packet, curr_time, src_seq, dst_seq);
	TcpSession::send_data(reinterpret_cast<const uint8_t*>(get_response(1)), strlen(get_response(1)), dst_packet, curr_time, dst_seq, src_seq);

	// Conversation No. 3
	TcpSession::send_data(reinterpret_cast<const uint8_t*>(get_request(2)), strlen(get_request(2)), src_packet, curr_time, src_seq, dst_seq);
	TcpSession::send_data(reinterpret_cast<const uint8_t*>(get_response(2)), strlen(get_response(2)), dst_packet, curr_time, dst_seq, src_seq);

	src_packet.reset_tcp_payload();
	dst_packet.reset_tcp_payload();
	TcpSession::send_finish_sequence(src_packet, dst_packet, curr_time, src_seq, dst_seq);
}

void generate_persist_connection()
{
	if (!init_dumper(OUTPUT_FILE_NAME)) {
		cout << "Could not initialize dumper!" << endl;
		return;
	}

	intialize_src_and_dst_packets();

	generate_conversations();

	cout << "Sample traffic is created in '" << OUTPUT_FILE_NAME << "' file!" << endl;
	close_dumper();
}

