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

#include <string>
#include <cstdio>

#include "Dumper.h"

using namespace std;
using namespace Dumper;

#define MAX_TRANSMITION_UNIT 1600
#define EXIT_ERROR(...) do { fprintf(stderr, ##__VA_ARGS__); return 1; } while(0)

int main(int argc, char** argv)
{
	if (argc < 3)
		EXIT_ERROR("	usage: bin2pcap <binary_input_file> <pcap_output_file>\n");

	FILE* binary_file = nullptr;
	if ((binary_file = fopen(argv[1], "rb")))
		EXIT_ERROR("Could not open input file '%s'.\n", argv[1]);

	if (!init_dumper(string(argv[2])))
		EXIT_ERROR("Could not initialize pcap file '%s'.\n", argv[2]);

	// File size;
	fseek(binary_file, 0, SEEK_END);
	int file_size = ftell(binary_file);
	fseek(binary_file, 0, SEEK_SET);

	if (file_size > MAX_TRANSMITION_UNIT)
		EXIT_ERROR("File size is larger than MTU(%d) bytes.\n", MAX_TRANSMITION_UNIT);

	unsigned char buffer[MAX_TRANSMITION_UNIT];
	fread(buffer, file_size, 1, binary_file);
	dump_packet(buffer, file_size, { 0, 0 });
	close_dumper();
	return 0;
}
