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
#include <iomanip>
#include <cstring>

#include "Packet.h"
#include "Dumper.h"
#include "SendData.h"

using namespace std;
using namespace Dumper;

int main(int argc, char** argv)
{
	cout << endl;
	cout << "---------------------------------" << endl;
	cout << "  This is TCP packet generator." << endl;
	cout << "---------------------------------" << endl << endl;

	if (!init_dumper("./TCP-GEN.pcap")) {
		cout << "Could not initialize dumper!" << endl;
		return 1;
	}

	if (argc <= 1)
		send();
	else if (argv[1][0] == 'm')		// Max MTU packet
		packet_1600();
	else if (argv[1][0] == 'o')		// Out of order
		send_out_of_order();
	else if (argv[1][0] == 'l')		// Lost packets
		send_out_of_order_lost();
	else if (argv[1][0] == 't')		// Test packets
		send_test();

	close_dumper();

	return 0;
}

