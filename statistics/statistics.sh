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

# Web site: https://ask.wireshark.org/questions/13096/how-to-get-statistics-conversation-list-tcp-information-in-a-text-file

if [[ $# < 1 ]]
then
	echo "File name required!"
	exit 1
fi

if [[ ! -e $1 ]]
then
	echo "File '$1' not exists!"
	exit 1
fi

function stats()
{
	echo "Generating '$2' stats from input '$1' file to '$2' ouput file."
	tshark -r $1 -q -z conv,$2 > $3
}

stats $1  eth   eth.csv
stats $1  fc    fc.csv
stats $1  fddi  fddi.csv
stats $1  ip    ip.csv
stats $1  ipv6  ipv6.csv
stats $1  ipx   ipx.csv
stats $1  tcp   tcp.csv
stats $1  udp   udp.csv
