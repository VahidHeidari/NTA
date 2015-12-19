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

#include "RawData.h"

#include <fstream>

using namespace std;

bool check_offset_is_valid(ifstream& file, size_t offset)
{
	file.seekg(offset);
	return static_cast<size_t>(file.tellg()) == offset;
}

bool RawData::read(const char* path, size_t start, size_t size, uint8_t* output_buffer)
{
	// Open file as input and binary.
	ifstream file(path, ifstream::binary);
	if (!file.is_open() || !file.good())
		return false;

	// Check start and end offsets are in file size.
	if (!check_offset_is_valid(file, start) || !check_offset_is_valid(file, start + size))
		return false;

	file.seekg(start);		// Seek to start offset.
	file.read(reinterpret_cast<char*>(output_buffer), size);		// Read and copy content of file into output buffer.

	return true;
}

bool RawData::read(const string& path, size_t start, size_t size, uint8_t* output_buffer)
{
	return read(path.c_str(), start, size, output_buffer);
}

