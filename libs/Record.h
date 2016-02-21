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

#ifndef RECORD_H_
#define RECORD_H_

#include <string.h>
#include <stdint.h>		// uint8_t, uint16_t, ...
#include <stddef.h>		// size_t

class Record {
public:
	Record() : data(nullptr), size(0) {}
	Record(uint8_t* d, size_t s) : data(d), size(s) {}
	Record(const Record& r) : data(nullptr), size(0) { copy(r); }
	virtual ~Record() { free(); }

	virtual bool operator==(const Record& r) const
	{
		if (size != r.size)
			return false;

		return memcmp(data, r.data, size) == 0;
	}

	virtual bool operator!=(const Record& r) const
	{
		return !(*this == r);
	}

	virtual Record& operator=(const Record& r)
	{
		copy(r);
		return *this;
	}

	virtual void free()
	{
		delete[] data;
		data = nullptr;
		size = 0;
	}

	virtual void copy(const Record& r)
	{
		free();

		if (r.size) {
			data = new uint8_t[r.size];
			memcpy(data, r.data, r.size);
			size = r.size;
		}
	}

	virtual void copy(uint8_t* data, size_t size)
	{
		Record r(data, size);
		copy(r);
	}

	uint8_t* data;
	size_t size;
};

#endif

