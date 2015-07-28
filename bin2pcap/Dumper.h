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

#ifndef DUMPER_H_
#define DUMPER_H_

#include <string>

#include <pcap/pcap.h>

class Packet;
struct timeval;

namespace Dumper
{
bool init_dumper(std::string output_path);
bool close_dumper();
void dump_packet(const Packet& packet, const timeval& tm);
void dump_packet(const void* packet, size_t length, const timeval& tm);

extern pcap_dumper_t* dumper;
extern pcap_t* handel;
extern pcap_pkthdr pkthdr;
} // namespace Dumper

#endif

