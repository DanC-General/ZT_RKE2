#!/bin/bash
# Edit a file
sshpass -p "test" ssh -o StrictHostKeyChecking=no -p 30002 root@"$IP" "ls; 
cd .; 
sleep $((RANDOM % 11)); 
echo \"Added new line\" >> new.txt; 
sleep $((RANDOM % 11)); 
sed 's/.*/sededited/g' new.txt; 
"
