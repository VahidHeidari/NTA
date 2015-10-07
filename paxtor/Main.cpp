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

#include <iostream>
#include <set>

#include "PcapReader.h"
#include "ForwardPcapReader.h"
#include "PcapWriter.h"

using namespace std;

constexpr int MANDATORY_ARGV = 5;
constexpr int MODE_SELECT_IDX = 1;
constexpr int INPUT_FILE_IDX = 2;
constexpr int OUTPUT_FILE_IDX = 3;
constexpr int PACKET_NUM_START_IDX = 4;

int read_all(int argc, char** argv)
{
	cout << "PaXtoR initializing reader . . ." << endl;
	PcapReader reader;
	if (!reader.init(argv[INPUT_FILE_IDX])) {
		cerr << "Could not initialize reader!" << endl;
		cerr << "PaXtoR exits focibly!" << endl;
		return 1;
	}

	cout << "    Reading file . . ." << endl;
	if (!reader.read_all()) {
		cerr << "Could not read input file '"<< argv[INPUT_FILE_IDX] << "'!" << endl;
		cerr << "PaXtoR exits focibly!" << endl;
		return 1;
	}
	reader.rewind();
	reader.reset_idx();

	cout << "PaXtoR initializing writer . . ." << endl;
	PcapWriter writer;
	if (!writer.init(argv[OUTPUT_FILE_IDX])) {
		cerr << "PaXtoR could not initialize writer!" << endl;
		cerr << "PaXtoR exits focibly!" << endl;
		return 1;
	}

	cout << "PaXtoR parsing packet numbers . . . " << endl;
	set<int> packet_cnt;
	argc -= PACKET_NUM_START_IDX;
	argv = &argv[PACKET_NUM_START_IDX];
	int i = 0;
	while (argc--) {
		int pktno = atoi(argv[i]);
		packet_cnt.insert(pktno);
		++i;
	}

	cout << "PaXtoR initialized successfuly." << endl;
	cout << "    PaXtoR reading parsed packet numbers . . ." << endl;
	for (auto itr : packet_cnt) {
		Record r;
		if (!reader.read_record(itr, r)) {
			cerr << "PaXtoR could not read record " << itr << '!' << endl;
			cerr << "PaXtoR exits focibly!" << endl;
			return 1;
		}
		writer.add_record(&r);
	}

	cout << endl;
	cout << "    PaXtoR readed " << reader.num_of_records() << " number of records." << endl;
	cout << "    Writing records . . ." << endl;
	if (!writer.write_all()) {
		cerr << "PaXtoR could not write!" << endl;
		cerr << "PaXtoR exits focibly!" << endl;
		return 1;
	}

	cout << endl;
	cout << "PaXtoR finished successfuly." << endl;
	return 0;
}

int read_forward(int argc, char** argv)
{
	const char* input_file = argv[INPUT_FILE_IDX];
	const char* output_file = argv[OUTPUT_FILE_IDX];

	cout << "PaXtoR parsing packet numbers . . . " << endl;
	set<int> packet_cnt;
	argc -= PACKET_NUM_START_IDX;
	argv = &argv[PACKET_NUM_START_IDX];
	int i = 0;
	while (argc--) {
		int pktno = atoi(argv[i]);
		packet_cnt.insert(pktno);
		++i;
	}

	cout << "PaXtoR initializing reader . . ." << endl;
	ForwardPcapReader reader;
	if (!reader.init(input_file)) {
		cerr << "Could not initialize reader!" << endl;
		cerr << "PaXtoR exits focibly!" << endl;
		return 1;
	}

	cout << "PaXtoR initializing writer . . ." << endl;
	PcapWriter writer;
	if (!writer.init(output_file)) {
		cerr << "PaXtoR could not initialize writer!" << endl;
		cerr << "PaXtoR exits focibly!" << endl;
		return 1;
	}

	cout << "    PaXtoR reading parsed packet numbers . . ." << endl;
	for (auto& itr : packet_cnt) {
		cout << " Reading packet #" << itr << " . . ." << endl;

		Record r;
		if (!reader.read_record(itr, r)) {
			cerr << "Could not read input file '"<< input_file << "'!" << endl;
			cerr << "PaXtoR exits focibly!" << endl;

			if (!reader.num_of_records())
				return 1;

			cout << " There are some packets in my list. Try to write them . . ." << endl;
		}

		writer.add_record(&r);
	}

	cout << "    PaXtoR readed " << reader.num_of_records() << " number of records." << endl;
	cout << "    Writing records . . ." << endl;
	if (!writer.write_all()) {
		cerr << "PaXtoR could not write!" << endl;
		cerr << "PaXtoR exits focibly!" << endl;
		return 1;
	}

	cout << endl;
	cout << "PaXtoR finished successfuly." << endl;
	return 0;
}

int main(int argc, char** argv)
{
	if (argc < MANDATORY_ARGV) {
		cerr << endl << "Usage : paxtor F|A input_file output_file packet_numbers" << endl;
		cerr << "    F : Forward reading without buffering." << endl;
		cerr << "    A : Read ALL packets from input and buffers them entirely." << endl << endl;
		cerr << "PaXtoR exits focibly!" << endl;
		return 1;
	}

	int return_value = 1;
	if (argv[MODE_SELECT_IDX][0] == 'A')
		return_value = read_all(argc, argv);
	else if (argv[MODE_SELECT_IDX][0] == 'F')
		return_value = read_forward(argc, argv);
	else
		cerr << "Bad mode selector of \'" << argv[MODE_SELECT_IDX][0] << "\'!" << endl;

	return return_value;
}

