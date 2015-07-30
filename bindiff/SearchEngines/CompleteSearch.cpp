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

#include "CompleteSearch.h"

using namespace std;

bool CompleteSearch::init()
{
	if (!r1 || !r2 || !w) {
		cerr << "Could not initialize complete search engine!" << endl;
		return false;
	}

	if (!r1->read_all() || !r2->read_all()) {
		cerr << "Could not read all records!" << endl;
		return false;
	}

	r1->reset_idx();
	r2->reset_idx();

	return true;
}

bool CompleteSearch::search()
{
	Record rec1, rec2;

	while (r1->next_record(rec1)) {
		while (r2->next_record(rec2)) {
			if (rec1 == rec2)
				break;
		}

		if (r2->eor() && rec1 != rec2) {
			Record* rec = new Record();
			rec->copy(rec1);
			w->add_record(rec);
		}
	}

	if (!w->write_all()) {
		cerr << "Writing failed!" << endl;
		return false;
	}

	return true;
}
