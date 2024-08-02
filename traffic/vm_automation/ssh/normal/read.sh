#!/bin/bash
# Read a file
sshpass -p "test" ssh -o StrictHostKeyChecking=no -p 30002 root@"$IP" "ls; 
cd .; 
sleep $((RANDOM % 11)); 
cat .profile; 
sleep $((RANDOM % 11)); 
head .profile;
tail .profile;
"

