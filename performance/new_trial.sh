dir=$(date | tr ' ' '_' | tr ':' '_')
echo "MAKE SURE TO ADD VM MALICIOUS LOGS"
cd /home/dc/ZT_RKE2/performance && mkdir "$dir" 
cp /home/dc/ZT_RKE2/module/logs/py.log /home/dc/ZT_RKE2/performance/$dir/py.log
cp /home/dc/ZT_RKE2/traffic/vm_automation/malicious.log /home/dc/ZT_RKE2/performance/$dir/mal.log

echo "Moving /home/dc/ZT_RKE2/dump.pcap"
sudo tcpdump -r "/home/dc/ZT_RKE2/dump.pcap" -c 20000 -w "/home/dc/ZT_RKE2/performance/$dir/head.pcap" 
pcapsampler -m COUNT_RAND_UNIFORM -r 150 "/home/dc/ZT_RKE2/dump.pcap" "/home/dc/ZT_RKE2/performance/$dir/sample.pcap"
mergecap -w "/home/dc/ZT_RKE2/performance/$dir/sample_combined.pcap" "/home/dc/ZT_RKE2/performance/$dir/head.pcap" "/home/dc/ZT_RKE2/performance/$dir/sample.pcap"

source /home/dc/ZT_RKE2/module/venv/bin/activate && python3 /home/dc/ZT_RKE2/module/Kit_Agent/example.py -f "/home/dc/ZT_RKE2/performance/$dir/sample_combined.pcap" -t "/home/dc/ZT_RKE2/performance/$dir/sample_output.log"