#!/bin/bash

sudo gnome-terminal -- sh -c "bash -c \"cd module && make && ./scrape; bash\""

sudo gnome-terminal -- sh -c "bash -c \"cd module && python3 rules.py; bash\""
sleep 1 
cd traffic && ./send_traffic.sh;./send_traffic.sh; cd ..
read -p "Continue?" 
for i in $(ps -ef | grep gnome-terminal | tr -s [:space:] | cut -d' ' -f 2 ); 
	do sudo kill -INT $i; 
done 


