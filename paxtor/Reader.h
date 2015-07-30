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

#ifndef READER_H_
#define READER_H_

#include <list>
#include <fstream>

#include "Record.h"

class Reader {
public:
	Reader()
	: idx(0)
	{
	}

	virtual ~Reader()
	{
		free();
	}

	virtual bool init(const char* input_path) = 0;
	virtual bool read_record() = 0;
	virtual bool read_record(int i, Record& r) = 0;
	virtual bool read_all() = 0;
	virtual int  num_of_records() = 0;
	virtual bool next_record(Record& record) = 0;
	virtual bool previous_record(Record& record) = 0;

	virtual bool eof()
	{
		return in_file.eof();
	}

	virtual bool eor()
	{
		return idx == (int)records.size();
	}

	virtual bool rewind()
	{
		in_file.seekg(0, std::ios_base::beg);
		return true;
	}

	virtual void free()
	{
		for (auto itr = records.begin(), itr_end = records.end(); itr != itr_end; ++itr)
			delete *itr;
		records.clear();
	}

	int get_curr_idx() const
	{
		return idx;
	}

	virtual void reset_idx()
	{
		idx = 0;
	}

protected:
	int idx;
	std::list<Record*> records;
	std::ifstream in_file;
};

#endif

