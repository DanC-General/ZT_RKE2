#!/bin/bash
# Script that closes the process using the socket 
#   for the malicious connection 

# args: host_ip host_port 
# Check 2 args 
echo "Attempting to kill: $1 , $2" 
# For local
find_and_kill(){ 
    PID=$(ss -p | grep "$1" | grep "$2" | cut -d"," -f 2 | cut -d= -f 2)
    echo "$PID"
    if [[ -n "$PID" ]] 
        then echo "Killing local $PID"
        whoami
        id -a
        sudo ip netns exec $i kill $PID 
        exit;
    fi
}
find_and_kill "$1" "$2" 
for i in $(ip netns | cut -d' ' -f 1); 
    do 
    PID=$(sudo ip netns exec $i ss -p | grep "$1" | grep "$2" | cut -d, -f2 | cut -d= -f2)
    echo "$PID"
    if [[ -n "$PID" ]] 
        # then sudo kill "$PID"
        then echo "Killing remote $PID"
        whoami
        id -a
        sudo ip netns exec $i kill $PID
        exit;
    fi
done 

