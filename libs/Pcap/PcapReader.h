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

#ifndef PCAP_READER_H_
#define PCAP_READER_H_

#include <string.h>

#include <iostream>
#include <string>

#include "Reader.h"

class PcapReader : public Reader {
public:
	PcapReader()
	: Reader()
	, path()
	{
		itr = records.begin();
	}

	~PcapReader() override
	{
		free();
		in_file.close();
	}

	bool init(const char* in_file) override
	{
		if (strlen(in_file) == 0) {
			std::cerr << "Could not initialize PCAP reader! Input file name is not valid." << std::endl;
			return false;
		}

		path.assign(in_file);

		//in_file.open();
		return true;
	}

	bool read_record() override
	{
		return false;
	}

	void reset_idx() override
	{
		itr = records.begin();
		idx = 0;
	}

	int  num_of_records() override { return records.size(); }

	bool read_all() override;
	bool read_record(int i, Record& r) override;
	bool next_record(Record& record) override;
	bool previous_record(Record& record) override;

protected:
	std::string path;
	std::vector<Record*>::iterator itr;
};

#endif

