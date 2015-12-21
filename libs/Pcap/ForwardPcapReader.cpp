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

#include "ForwardPcapReader.h"

#include <iostream>

using namespace std;

ForwardPcapReader::ForwardPcapReader()
: PcapReader()
, packet_header(nullptr)
, packet_data(nullptr)
, handel(nullptr)
, current_packet_num(0)
{
}

bool ForwardPcapReader::init(const char* file_path)
{
	if (!PcapReader::init(file_path))
		return false;

	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	handel = pcap_open_offline(path.c_str(), pcap_errbuf);

	if (!handel) {
		cerr << "Could not open file \"" << path << "\"!" << endl;
		cerr << "    PCAP error : \"" << pcap_errbuf << "\"." << endl;
		return false;
	}

	return true;
}

bool ForwardPcapReader::read_record(int i, Record& r)
{
	// Out of range, and backward reading.
	if (i <= current_packet_num || i < 0)
		return false;

	int ret;
	while ((ret = pcap_next_ex(handel, &packet_header, &packet_data)) > 0) {
		if (++current_packet_num < i)
			continue;		// Read next packet.

		// Copy packet.
		size_t data_length = sizeof(pcap_pkthdr) + packet_header->len;
		u_char* data = new u_char[data_length];
		memcpy(data, packet_header, sizeof(pcap_pkthdr));						// Copy header information.
		memcpy(data + sizeof(pcap_pkthdr), packet_data, packet_header->len);	// Copy packet data.

		Record* record = new Record();
		record->copy(data, data_length);
		records.push_back(record);

		r = *record;		// Copy to output

		return true;
	}

	if (ret == -2 && i == current_packet_num)		// End of file reached.
		return true;

	return false;		// PCAP reading error, or out of range packet number.
}

void ForwardPcapReader::free()
{
	PcapReader::free();

	pcap_close(handel);
	handel = nullptr;
}

