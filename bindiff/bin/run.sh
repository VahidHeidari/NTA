#!/bin/bash

#./bindiff /home/pcap/_tmp_v6-http.cap /home/pcap/HTTP.cap out1.cap
#./bindiff /home/pcap/HTTP.cap /home/pcap/_tmp_v6-http.cap out1.cap
#./bindiff /home/pcap/http.cap /home/pcap/HTTP.cap out1.cap
#./bindiff /home/pcap/HTTP.cap /home/pcap/HTTP.cap out1.cap

../../bin/bindiff/bindiff chk16 HTTP.cap _tmp_v6-http.cap out1.cap

