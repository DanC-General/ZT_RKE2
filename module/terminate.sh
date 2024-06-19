#!/bin/bash
# Script that closes the process using the socket 
#   for the malicious connection 

# args: svc_port host_port 
# Check 2 args 
echo "Attempting to kill: $1 , $2" 
# For local
PID=$(ss -p | grep "$1" | grep "$2" | cut -d"," -f 2 | cut -d= -f 2)
kill "$PID"

# For remote 
sudo conntrack -D -p tcp --sport "$2" 