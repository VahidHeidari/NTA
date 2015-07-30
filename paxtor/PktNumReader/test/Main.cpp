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

#include "PktNumReader.h"

#include <iostream>

using namespace std;

int main()
{
	PktNumReader pkt_num_reader;
	if (!pkt_num_reader.read("../test.txt")) {
		cerr << "Could no read input file!" << endl;
		return 1;
	}

	cout << "Packets are:" << endl;
	for (int cnt : pkt_num_reader.get_packets())
		cout << cnt << ", ";
	cout << endl;

	return 0;
}

