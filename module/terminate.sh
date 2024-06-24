#!/bin/bash
# Script that closes the process using the socket 
#   for the malicious connection 

# args: host_ip host_port 
# Check 2 args 
echo "Attempting to kill: $1 , $2" 
# For local
find_and_kill(){ 
    PID=$(ss -p | grep "$1" | grep "$2" | cut -d"," -f 2 | cut -d= -f 2)
    if [[ -n "$PID" ]] 
        then kill "$PID"
        exit;
    fi
}
find_and_kill "$1" "$2" 
for i in $(ip netns | cut -d' ' -f 1); 
    do sudo ip netns exec $i ss -p | grep "$1" | grep "$2" | cut -d, -f2 | cut -d= -f2 | sudo xargs kill 
done 

