#!/bin/bash

./build/tests/pog_tests && \
	lcov --directory . --capture --output-file coverage.info && \
	lcov --remove coverage.info '/usr/*' '*/tests/*' --output-file coverage.info && \
	lcov --list coverage.info
