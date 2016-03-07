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

#ifndef CHKSUM_SEARCH_H_
#define CHKSUM_SEARCH_H_

#include <map>
#include <vector>

#include "SearchEngine.h"

/**
 * Complete search is very slow for big PCAPs in practice, so I need a faster
 * search than complete search among above of 2 millions of packets, and above
 * 1GB of PCAP file.
 *
 * I decided to hash each packet and search among hashed list of packet. Speed
 * of search is depends on hash function.
 *
 * In this class I used a simple check sum function for hashing.
 *
 *
 *  Search algorithm:
 * -------------------
 *
 * Read next record.
 * Search check sum.
 * If not exists output and go to next record.
 *    If exists iterate through collision list.
 *    		If not exist output.
 *    		Go to next record.
 *
 * I tested this method with a 4GB pcap with newar 9 millions of packets. It is
 * very fast :)
 */
class ChkSumSearch : public SearchEngine
{
public:
	bool init() override;
	bool search() override;
	bool finish() override;

private:
	/// Input 1 data structures
	typedef uint16_t ChkSumType;
	typedef std::pair<int, Record> ChkCollisionListRecordType;
	typedef std::vector<ChkCollisionListRecordType> ChkCollisionList;
	typedef std::map<ChkSumType, ChkCollisionList> ChkMap;

	/// Input 2 data structures
	typedef std::pair<ChkSumType, Record> ChkListRecordType;
	typedef std::vector<ChkListRecordType> ChkList;

	void print_init_log() const;
	void print_unique_log() const;

	/// Searching data structures
	ChkMap chk_packets_input1;
	ChkList chk_packets_input2;
};

#endif

