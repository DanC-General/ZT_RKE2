if [[ -z "$1" ]]; then
    echo "Requires input pcap file."
    exit
fi 
echo "Parsing $1 to $1\_sampled"
sudo tcpdump -r "$1" -c 20000 -w "$1_head.pcap" 
pcapsampler -m COUNT_RAND_UNIFORM -r 170 "$1" "$1_sampled.pcap"
mergecap -w "$1_combined.pcap" "$1_head.pcap" "$1_sampled.pcap"