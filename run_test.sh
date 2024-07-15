#!/bin/bash
sudo gnome-terminal -- sh -c "bash -c \"cd module && make && ./scrape; bash\""
sudo gnome-terminal -- sh -c "bash -c \"cd module && source venv/bin/activate && cd Kit_Agent && python3 rules.py; bash\""
#sleep 1;cd traffic && for i in {1..10}; do ./send_traffic.sh; done; cd .. 
#sleep 1; cd traffic && for i in {1..10}; do ./send_traffic.sh; done; cd ..
read -p "Continue?" 
for i in $(ps -ef | grep gnome-terminal | tr -s [:space:] | cut -d' ' -f 2 ); 
	do sudo kill -INT $i; 
done 
