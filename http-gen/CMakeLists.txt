#
# HttpGen is a HTTP sample traffic generator.
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
project(HttpGen)

set(CMAKE_USE_RELATIVE_PATHS true)

include_directories(
	${CMAKE_SOURCE_DIR}/libs
	${CMAKE_SOURCE_DIR}/libs/Pcap
	${CMAKE_SOURCE_DIR}/tcp)

add_executable(http-gen
	HttpContent.cpp
	Main.cpp
	ScenarioNo1.cpp
	${CMAKE_SOURCE_DIR}/tcp/TcpSession.cpp)

target_link_libraries(http-gen
	utils
	pcap)

