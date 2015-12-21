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

#ifndef FORWARD_PCAP_READER_H_
#define FORWARD_PCAP_READER_H_

#include "PcapReader.h"

#include <pcap.h>

class ForwardPcapReader : public PcapReader
{
public:
	ForwardPcapReader();

	bool read_all() override { return false; }
	bool next_record(Record& record) override { (void)record; return false; }
	bool previous_record(Record& record) override { (void)record; return false; }

	bool init(const char* file_path) override;
	bool read_record(int i, Record& r) override;
	void free() override;

private:
	pcap_pkthdr* packet_header;
	const u_char* packet_data;
	pcap_t* handel;
	int current_packet_num;
};

#endif

