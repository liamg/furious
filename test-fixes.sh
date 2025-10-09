#!/bin/bash

echo "=== Testing Furious Scanner Fixes ==="
echo

echo "1. Testing host detection fix (Issue #12):"
echo "Command: ./furious -s connect -p 80,443 google.com"
./furious -s connect -p 80,443 google.com
echo

echo "2. Testing filtered ports detection (Issue #7):"
echo "Command: ./furious -s connect -p 80,443,8080,9999 -t 2000 google.com"
./furious -s connect -p 80,443,8080,9999 -t 2000 google.com
echo

echo "3. Testing JSON output (Issue #14):"
echo "Command: ./furious -s connect -p 80,443,8080 -j google.com"
./furious -s connect -p 80,443,8080 -j google.com
echo

echo "4. Testing multiple hosts with JSON:"
echo "Command: ./furious -s connect -p 80,443 -j -u google.com github.com"
./furious -s connect -p 80,443 -j -u google.com github.com
echo

echo "=== All tests completed! ==="