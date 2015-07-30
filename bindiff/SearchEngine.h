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

#ifndef SEARCH_ENGINE_H_
#define SEARCH_ENGINE_H_

#include "Reader.h"
#include "Writer.h"

class SearchEngine {
public:
	SearchEngine()
	: r1(nullptr)
	, r2(nullptr)
	, w(nullptr)
	{
	}

	virtual ~SearchEngine()
	{
		delete r1;
		delete r2;
		delete w;
		r1 = nullptr;
		r2 = nullptr;
		w  = nullptr;
	}

	virtual bool init() = 0;
	virtual bool search() = 0;
	virtual bool finish() = 0;

	void set_r1(Reader* r) { r1 = r; }
	Reader* get_r1() const { return r1; }

	void set_r2(Reader* r) { r2 = r; }
	Reader* get_r2() const { return r2; }

	void set_writer(Writer* w) { this->w = w; }
	Writer* get_writer() const { return w; }

protected:
	Reader* r1;
	Reader* r2;
	Writer* w;
};

#endif

