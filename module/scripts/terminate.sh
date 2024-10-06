#!/bin/bash
# Script that closes the process using the socket 
#   for the malicious connection 

# args: host_ip host_port 
# Check 2 args 
echo "Attempting to kill: $1 , $2" 
# Checks local processes for the correct ip:port mapping of the connection.
#   Terminates it if it exists.
find_and_kill(){ 
    PID=$(ss -p | grep "$1" | grep "$2" | cut -d"," -f 2 | cut -d= -f 2)
    # echo "$PID"
    if [[ -n "$PID" ]] 
        then echo "Killing local $PID"
        sudo kill -9 "$PID" 
        exit;
    fi
}
# Iterates over all the network namespaces used by the pods,
#   checks if the correct ip:port mapping exists, and will
#   terminate it if it does. 
find_and_kill "$1" "$2" 
for i in $(ip netns | cut -d' ' -f 1); 
    do 
    PID=$(sudo ip netns exec $i ss -p | grep "$1" | grep "$2" | cut -d, -f2 | cut -d= -f2)
    # echo "$PID"
    if [[ -n "$PID" ]] 
        # then sudo kill "$PID"
        then echo "Killing remote $PID in netns $i"
        sudo ip netns exec "$i" kill -9 $PID
        exit;
    fi
done 

