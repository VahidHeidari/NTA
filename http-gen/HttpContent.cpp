/**
 * HttpGen is a HTTP sample traffic generator.
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

#include "HttpContent.h"

namespace HttpContent
{

static const char req_1[] = "GET / HTTP/1.1\r\n"
                            "Host: www.sample-test-example-generated.com\r\n"
                            "Connection: keep-alive\r\n"
                            "Cookie: This is some cookie!\r\n"
                            "\r\n";

static const char res_1[] = "HTTP/1.0 200 OK\r\n"
                            "Content-Type: text/plain\r\n"
                            "Content-Length: 23\r\n"
                            "\r\n"
                            "This is test content!\r\n";

static const char req_2[] = "GET /mail/index.html HTTP/1.1\r\n"
                            "Host: www.sample-mail-host-example.com\r\n"
                            "Connection: keep-alive\r\n"
                            "\r\n";

static const char res_2[] = "HTTP/1.0 200 OK\r\n"
                            "Content-Type: text/plain\r\n"
                            "Content-Length: 32\r\n"
                            "\r\n"
                            "This is test web mail service!\r\n";

static const char req_3[] = "GET /content/data.xml HTTP/1.1\r\n"
                            "Host: www.some-content-container.com\r\n"
                            "Connection: keep-alive\r\n"
                            "\r\n";

static const char res_3[] = "HTTP/1.0 200 OK\r\n"
                            "Connection: close\r\n"
                            "Content-Type: text/xml\r\n"
                            "Content-Length: 29\r\n"
                            "\r\n"
                            "<Data>Some Test Data</Data>\r\n";

static const char* requests[] = {
	req_1,
	req_2,
	req_3
};

static const char* responses[] = {
	res_1,
	res_2,
	res_3
};

size_t get_requests_size()
{
	return sizeof(requests) / sizeof(requests[0]);
}

size_t get_responses_size()
{
	return sizeof(responses) / sizeof(responses[0]);
}

const char* get_request(size_t i)
{
	if (i < get_requests_size())
		return requests[i];
	return nullptr;
}

const char* get_response(size_t i)
{
	if (i < get_responses_size())
		return responses[i];
	return nullptr;
}

}

