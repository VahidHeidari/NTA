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
#include "PcapWriter.h"

using namespace std;

int main(int argc, char** argv)
{
	if (argc < 4) {
		cerr << endl << "Usage : paxtor input_file output_file packet_numbers" << endl << endl;
		cerr << "PaXtoR exits focibly!" << endl;
		return 1;
	}

	cout << "PaXtoR initializing reader . . ." << endl;
	PcapReader reader;
	if (!reader.init(argv[1])) {
		cerr << "Could not initialize reader!" << endl;
		cerr << "PaXtoR exits focibly!" << endl;
		return 1;
	}

	cout << "    Reading file . . ." << endl;
	if (!reader.read_all()) {
		cerr << "Could not read input file '"<< argv[1] << "'!" << endl;
		cerr << "PaXtoR exits focibly!" << endl;
		return 1;
	}
	reader.rewind();
	reader.reset_idx();

	cout << "PaXtoR initializing writer . . ." << endl;
	PcapWriter writer;
	if (!writer.init(argv[2])) {
		cerr << "PaXtoR could not initialize writer!" << endl;
		cerr << "PaXtoR exits focibly!" << endl;
		return 1;
	}

	cout << "PaXtoR parsing packet numbers . . . " << endl;
	set<int> packet_cnt;
	argc -= 3;
	argv = &argv[3];
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

