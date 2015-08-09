#
# PaxTor is a pcap processor.
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

cmake_minimum_required(VERSION 2.8)
project(paxtor)
set(CMAKE_USE_RELATIVE_PATHS true)
add_definitions(-g -std=c++11 -Wall -Wextra -pedantic)
include_directories(../Commons ../Commons/Pcap)
add_executable(paxtor
	Main.cpp
	../Commons/Pcap/PcapReader.cpp
	../Commons/Pcap/PcapWriter.cpp)
target_link_libraries(paxtor -lpcap)
