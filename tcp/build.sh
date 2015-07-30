#!/bin/bash

#
# NTA (Network Traffic Analyser) is contains simple tools for analysing
# netwrok traffic.
#
# Copyright (C) 2015  Vahid Heidari (DeltaCode)
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

echo "Building project TCP genrator . . ."

if [ ! -d bin ]; then	# If 'bin' directory does not exists, create it.
	mkdir bin
fi

cd bin
cmake .. &&  make && ./tcp-gen $@ > out.txt

echo End of building!
