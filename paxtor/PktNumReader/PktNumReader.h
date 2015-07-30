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

#ifndef PKT_NUM_READER_H_
#define PKT_NUM_READER_H_

#include <set>

class PktNumReader {
public:
	typedef std::set<int> PacketList;

	PktNumReader() = default;

	bool read(const char* path);

	bool is_contained(int cnt)
	{
		PacketList::iterator itr;
		if (packets.empty() || ((itr = packets.find(cnt)) == packets.end()))
			return false;

		return true;
	}

	bool remove_packet(int cnt)
	{
		return packets.erase(cnt) != 0;
	}

	bool add_packet(int cnt)
	{
		packets.insert(cnt);
		return true;
	}

	void set(PacketList packets) { this->packets = packets; }
	PacketList get_packets() const { return packets; }

protected:
	PacketList packets;
};

#endif

