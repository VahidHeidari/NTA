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

#include "ChkSumSearch.h"

#include <fstream>
#include <iomanip>
#include <iostream>

#include "Utilities.h"

using namespace std;
using namespace Utilities;

extern bool finished;

bool ChkSumSearch::init()
{
	if (!r1 || !r2 || !w) {
		cerr << "Could not initialize chksum search engine!" << endl;
		return false;
	}

	if (!r1->read_all() || !r2->read_all()) {
		cerr << "Could not read all records!" << endl;
		return false;
	}

	r1->reset_idx();
	r2->reset_idx();

	for (int i = 1; i <= r2->num_of_records(); ++i) {
		cout << "\rchecksum calculation of input2 "
			<< '#' << i << " of #" << r2->num_of_records()
			<< "   %" << (int)((float)i / (float)r2->num_of_records() * 100);
		Record r;
		r2->next_record(r);
		ChkSumType checksum = checksum16(r.data, r.size);
		chk_packets_input1[checksum].push_back(make_pair(i, r));
	}

	cout << endl << endl;
	for (int i = 1; i <= r1->num_of_records(); ++i) {
		cout << "\rChecksum calculation of input1 "
			<< '#' << i << " of #" << r1->num_of_records()
			<< "   %" << (int)((float)i / (float)r1->num_of_records() * 100);
		Record r;
		r1->next_record(r);
		chk_packets_input2.push_back(make_pair(checksum16(r.data, r.size), r));
	}

	cout << endl << endl;

	print_init_log();

	return true;
}

bool ChkSumSearch::search()
{
	ofstream log_file("chklog.log", ios::out);
	if (!log_file.is_open()) {
		cerr << "Cound not open log file!" << endl;
		return false;
	}
	log_file << endl;

	int packet_num = 0;
	for (auto& chk2 : chk_packets_input2) {
		if (finished)
			break;

		++packet_num;
		cout << "\rSearching packet #" << packet_num << " of #" << r1->num_of_records()
			<< " %" << (int)((float)packet_num / (float)r1->num_of_records() * 100);

		ChkSumType& check_sum = chk2.first;
		const auto& chk1 = chk_packets_input1.find(check_sum);	// Find check sum.

		if (chk1 == chk_packets_input1.end()) {					// If not exist then dump record.
			w->add_record(new Record(chk2.second));
			log_file << "input2 packet #" << dec << packet_num
				<< " with check 0x" << setw(4) << setfill('0') << hex << check_sum
				<< " not found in input1!" << endl;
			log_file.flush();
		}
		else {
			bool is_exist = false;
			for (const auto& coll_rec : chk1->second)				// Else iterate collision list.
				if (coll_rec.second == chk2.second) {
					is_exist = true;
					break;											// If exist continue searching.
				}

			if (!is_exist) {
				w->add_record(new Record(chk2.second));
				log_file << "input2 packet #" << dec << packet_num
					<< " with check 0x" << setw(4) << setfill('0') << hex << check_sum
					<< " not found in input1 list!" << endl;
				log_file.flush();
			}
		}
	}

	cout << endl << endl;

	if (!w->write_all()) {
		cerr << "Writing failed!" << endl;
		return false;
	}

	return true;
}

bool ChkSumSearch::finish()
{
	for (auto& itr : chk_packets_input1)
		for (auto& list_itr : itr.second)
			list_itr.second.free();

	for (auto& itr : chk_packets_input2)
		itr.second.free();

	return true;
}

void ChkSumSearch::print_init_log() const
{
	ofstream log_file("chklog.stat", ios::out);
	if (!log_file.is_open()) {
		cerr << "Could not open log file!" << endl;
		return;
	}

	log_file << "\n\n\n";
	log_file << "Logging starts . . ." << endl;
	log_file << "Input 1 packets : " << r1->num_of_records() << endl;
	log_file << "Input 2 packets : " << r2->num_of_records() << endl;

	// Dump input 1 packets statistic.
	log_file << endl;
	log_file << "Input 1 stats :" << endl;
	int packet_num = 0;
	for (const auto& itr : chk_packets_input1) {
		log_file << "    #" << setw(10) << setfill(' ') << left << dec << ++packet_num
			<< "Check 0x" << setw(4) << setfill('0') << hex << itr.first
			<< "    #" << dec << itr.second.size() << endl;
		log_file.flush();
	}

	// Dump input 2 packets statistics.
	log_file << endl;
	log_file << "Input 2 stats :" << endl;
	packet_num = 0;
	for (const auto& itr : chk_packets_input2) {
		log_file << "    #" << setw(10) << setfill(' ') << left << dec << ++packet_num
			<< "Check 0x" << setw(4) << setfill('0') << hex << itr.first << endl;
		log_file.flush();
	}

	log_file.close();
}

