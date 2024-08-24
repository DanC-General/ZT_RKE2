sudo sh -c "bash -c \"tcpdump -i any -w dump.pcap\"" &
sudo sh -c "bash -c \"cd module && make && ./scrape; bash\"" &
sudo sh -c "bash -c \"cd module && source venv/bin/activate && cd Kit_Agent && python3 rules.py; bash\"" 

# sudo sh -c bash -c "cd module && make && ./scrape &"
# sudo bash -c "cd module && source venv/bin/activate && cd Kit_Agent && python3 rules.py"
sleep 1 