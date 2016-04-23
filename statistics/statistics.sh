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

#
# Web site: https://ask.wireshark.org/questions/13096/how-to-get-statistics-conversation-list-tcp-information-in-a-text-file
#
#
# The out put of this script is not in csv (Comma Separated Values). If you want to get csv formated output,
# you have to write your own script for converting the out put to csv, or use GUI form this address:
#
# https://ask.wireshark.org/questions/22749/how-to-export-the-pcap-file-statistics-with-csv-file-format
#
# If you need the data in CSV format, there are (at least) these options:
#
#    * Use the GUI: Statistics -> Conversations -> TCP -> Copy. This will copy the screen content as CSV into the clipboard.
#    * Use tshark: tshark will not export the conversation data in CSV format, so you either convert it to CSV with Excel (while importing the data) or use a script (perl, python, watherver) to convert that output to csv.
#    * Extend the tshark code to export CSV structured data.
#

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

# Argument $1 is input file name.
# Argument $2 is protocol filter.
# Argument $3 is output file name.
function stats()
{
	echo "Generating '$2' stats from input '$1' file to '$2' ouput file."
	tshark -r $1 -q -z conv,$2 > $3
}

stats $1  eth   eth.stat
stats $1  fc    fc.stat
stats $1  fddi  fddi.stat
stats $1  ip    ip.stat
stats $1  ipv6  ipv6.stat
stats $1  ipx   ipx.stat
stats $1  tcp   tcp.stat
stats $1  udp   udp.stat

