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

#include <stdarg.h>

#include <iostream>

#include <signal.h>

#include "Reader.h"
#include "ReaderFactory.h"
#include "Record.h"
#include "SearchEngine.h"
#include "SearchEngineFactory.h"
#include "Writer.h"
#include "WriterFactory.h"

using namespace std;

#define MIN_REQUIRED_ARGS 4

static const char* VERSION = "1.0.0";

const char* engine;
const char* filetype;
const char* filename[3];

bool finished = false;

void signal_handler(int signum)
{
	(void)signum;
	finished = true;
}

template <bool version_only = false>
void print_help()
{
	putchar('\n');

	if (version_only) {
		printf("    version : %s\n", VERSION);
	} else {
		puts("Usage : bindiff engine [filetype] input1 input2 output\n");
		puts("    help        This help menu.");
		puts("    version     Versoin of this program.");
		puts("    engine      The searching engine. Engine types are as follows:");
		puts("                    comp    : Complete search engine.");
		puts("                    chk16   : Checksum16 hased search engine.");
		puts("    [filetype]  The input file type for comparing.\n");
		puts("        pcap        Search for differences of two pcap files.");
		printf("\n    version : %s\n", VERSION);
	}

	putchar('\n');
}

void exit_error(const char* fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	vfprintf(stderr, fmt, va);
	putchar('\n');
	va_end(va);

	exit(1);
}

bool find_filetype(const char* file_name)
{
	int i = -1;
	int len = strlen(file_name);

	for (i = len - 1; i >= 0; --i)
		if (file_name[i] == '.')
			break;

	if (i != -1 && (i + 1) < len) {
		filetype = &file_name[i + 1];
		return true;
	}

	filetype = nullptr;
	return false;
}

bool is_supported_filetype(const char* type)
{
	if (!type)
		return false;

	if (strncasecmp("pcap", type, 4) == 0)
		return true;
	else if (strncasecmp("cap", type, 3) == 0)
		return true;

	return false;
}

void parse_comand_line(int argc, char** argv)
{
	if (argc == 1) {
		if (strncasecmp("VERSION", argv[0], 7) == 0) {
			print_help<true>();
			exit(0);
		} else if (strncasecmp("HELP", argv[0], 4) == 0) {
			print_help();
			exit(0);
		} else
			exit_error("Unknown option! use help for more information.");
	}

	if (argc < MIN_REQUIRED_ARGS)
		exit_error("At least searching engine, two input file, and one output file is required!");

	engine = argv[0];
	if (argc == 4) {
		filename[0] = argv[1];
		filename[1] = argv[2];
		filename[2] = argv[3];
		filetype = nullptr;
	} else if (argc < 5) {
		filename[0] = argv[2];
		filename[1] = argv[3];
		filename[2] = argv[4];
		filetype = argv[0];
	}

	if (!filetype)
		find_filetype(filename[0]);

	if (!is_supported_filetype(filetype))
		exit_error("Unknown file type!");
}

int main(int argc, char** argv)
{
	signal(SIGINT, signal_handler);

	parse_comand_line(argc - 1, &argv[1]);

	// Debug only
	for (int i = 0; i < argc; ++i)
		cout << "argv[" << i << "] : " << argv[i] << endl;
	cout << endl;
	cout << "filetype:" << filetype << endl;
	cout << "Input1 : " << filename[0] << endl;
	cout << "Input2 : " << filename[1] << endl;
	if (filename[2]) cout << "output : " << filename[2] << endl;

	Reader* r1 = ReaderFactory::create(filetype);
	Reader* r2 = ReaderFactory::create(filetype);
	Writer* w  = WriterFactory::create(filetype);

	if (!r1->init(filename[0])
			|| !r2->init(filename[1])
			|| !w->init(filename[2]))
		exit_error("Could not initialize Readers or Writers!");

	SearchEngine* search_engine = SearchEngineFactory::create(engine);
	if (!search_engine) {
		delete r1;
		delete r2;
		delete w;

		exit_error("Could not create engine of type '%s'!", engine);
	}

	search_engine->set_r1(r1);
	search_engine->set_r2(r2);
	search_engine->set_writer(w);

	if (search_engine->init())
		search_engine->search();

	if (!search_engine->finish())
		exit_error("Could not finish search!");

	delete search_engine;

	return 0;
}

