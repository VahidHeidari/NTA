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

#include "PcapReader.h"

#include <string.h>

#include <pcap.h>

using namespace std;

bool PcapReader::read_all()
{
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handel = pcap_open_offline(path.c_str(), pcap_errbuf);

	if (!handel) {
		cerr << "Could not open file \"" << path << "\"!" << endl;
		cerr << "    PCAP error : \"" << pcap_errbuf << "\"." << endl;
		return false;
	}

	pcap_pkthdr* packet_header;
	const u_char* packet_data;

	int ret;
	while ((ret = pcap_next_ex(handel, &packet_header, &packet_data)) > 0) {
		size_t data_length = sizeof(pcap_pkthdr) + packet_header->len;
		u_char* data = new u_char[data_length];
		memcpy(data, packet_header, sizeof(pcap_pkthdr));						// Copy header information.
		memcpy(data + sizeof(pcap_pkthdr), packet_data, packet_header->len);	// Copy packet data.

		Record* record = new Record();
		record->copy(data, data_length);
		records.push_back(record);
	}

	pcap_close(handel);

	return true;
}

/*
bool PcapReader::next_record(Record& record)
{
	if (idx >= (int)records.size())
		return false;

	int i = 0;
	std::list<Record*>::const_iterator itr = records.begin();
	for (std::list<Record*>::const_iterator itr_end = records.end(); i != idx && itr != itr_end; ++itr, ++i)
		continue;
	record = **itr;
	++idx;
	return true;
}
*/

bool PcapReader::next_record(Record& record)
{
	if (itr == records.end())
		return false;
	record = **itr;
	++idx;
	++itr;
	return true;
}

/*
bool PcapReader::previous_record(Record& record)
{
	if (!records.size())
		return false;

	if (idx < 0)
		return false;

	--idx;
	int i = 0;
	std::list<Record*>::const_iterator itr = records.begin();
	for (std::list<Record*>::const_iterator itr_end = records.end(); i != idx && itr != itr_end; ++itr, ++i)
		continue;
	record = **itr;
	return true;
}
*/

bool PcapReader::previous_record(Record& record)
{
	if (idx < 0)
		return false;
	--idx;
	--itr;
	record = **itr;
	return true;
}

bool PcapReader::read_record(int i, Record& r)
{
	if (0 > i || i > (int)records.size())
		return false;

	Record rec;
	if (idx < i) {
		while (idx != i)
			next_record(rec);
	} else if (idx > i) {
		while (idx != i)
			previous_record(rec);
	}

	r = rec;
	return true;
}

