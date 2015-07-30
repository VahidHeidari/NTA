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

#ifndef PCAP_WRITER_H_
#define PCAP_WRITER_H_

#include <string.h>

#include <list>
#include <string>

#include "Writer.h"

class PcapWriter : public Writer {
public:
	~PcapWriter() override
	{
	}

	bool write_all() override;
	bool write_record() override;
	bool write_record(int i) override;
	bool next_record(Record&) override;
	bool previous_record(Record&) override;

	bool init(const char* out_path) override
	{
		if (strlen(out_path) == 0) {		// throw output to stdout.
			return false;
		}

		path.assign(out_path);

		return true;
	}


protected:
	std::string path;
	std::list<Record*>::iterator itr;
};

#endif

