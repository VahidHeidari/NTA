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

#include "PcapWriter.h"

#include <iostream>

#include <pcap.h>

using namespace std;

bool PcapWriter::write_all()
{
	if (!records.size()) {
		cerr << "There is not any records to write!" << endl;
		return false;
	}

	pcap_t* handel;
	if (!(handel = pcap_open_dead(DLT_EN10MB, 65535))) {
		cerr << "Could not open pcap to wirte!" << endl;
		return false;
	}

	pcap_dumper_t* dumper;
	if (!(dumper = pcap_dump_open(handel, path.c_str()))) {
		pcap_close(handel);
		cerr << "Could not open dumper." << endl;
		return false;
	}

	for (auto record : records)
		pcap_dump((u_char*)dumper, (pcap_pkthdr*)record->data, record->data + sizeof(pcap_pkthdr));

	pcap_close(handel);
	pcap_dump_close(dumper);

	return true;
}

bool PcapWriter::write_record()
{
	return false;
}

bool PcapWriter::write_record(int)
{
	return false;
}

bool PcapWriter::next_record(Record& record)
{
	if (itr == records.end())
		return false;
	record = **itr;
	++idx;
	++itr;
	return true;
}

bool PcapWriter::previous_record(Record& record)
{
	if (idx < 0)
		return false;
	--idx;
	--itr;
	record = **itr;
	return true;
}

