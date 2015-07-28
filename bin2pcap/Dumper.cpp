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

#include "Dumper.h"

#include <iostream>

#include "Packet.h"

using namespace std;

namespace Dumper
{
pcap_dumper_t* dumper;
pcap_t* handel;
pcap_pkthdr pkthdr;
}

void Dumper::dump_packet(const Packet& packet, const timeval& tm)
{
	Dumper::dump_packet(packet.get_frame(), packet.get_frame_size(), tm);
}

void Dumper::dump_packet(const void* packet, size_t length, const timeval& tm)
{
	// Pcap header
	pkthdr.ts = tm;
	pkthdr.caplen =	pkthdr.len = length;
	pcap_dump((u_char*)dumper, &pkthdr, (const u_char*)packet);
}

bool Dumper::init_dumper(std::string output_path)
{
	if (!(handel = pcap_open_dead(DLT_EN10MB, 65535))) {
		cerr << "Could not open pcap." << endl;
		return false;
	}

	int dl = pcap_datalink(handel);
	cout << "DataLink type : " << dl << endl;
	cout << "DataLink name : " << pcap_datalink_val_to_name(dl) << endl;
	cout << "DataLink desc : " << pcap_datalink_val_to_description(dl) << endl;

	if (!(dumper = pcap_dump_open(handel, output_path.c_str()))) {
		pcap_close(handel);
		cerr << "Could not open dumper." << endl;
		return false;
	}

	return true;
}

bool Dumper::close_dumper()
{
	cout << "Closing pcap and dumper . . ." << endl;
	pcap_close(handel);
	pcap_dump_close(dumper);

	return true;
}

