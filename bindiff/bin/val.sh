#!/bin/bash

valgrind --log-file=val.txt --track-fds=yes --track-origins=yes \
	--leak-check=full --show-leak-kinds=all --leak-resolution=high \
	./run.sh
