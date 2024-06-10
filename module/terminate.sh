#!/bin/bash
# Script that closes the process using the socket 
#   for the malicious connection 

# args: svc_port host_port 
# Check 2 args 
PID=$(ss -p | grep "$1" | grep "$2" | cut -d"," -f 2 | cut -d= -f 2)
kill "$PID"
