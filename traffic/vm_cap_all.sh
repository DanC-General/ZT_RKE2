for i in $($HOME/ZT_RKE2/traffic/svc_res.sh | grep '^|' | tail -n +2 | sed 's/^|//g'); 
    do 
    echo $i
    echo $i | cut -d'|' -f 2
    echo $i | cut -d'|' -f 1
    sudo gnome-terminal -- sh -c "bash -c \"sudo tcpdump -i $(echo $i | cut -d'|' -f 2) -w $(echo $i | cut -d'|' -f 1).pcap;bash\""
done 

read -p "Continue?" 
for i in $(ps -ef | grep gnome-terminal | tr -s '[:space:]' | cut -d' ' -f 2 ); 
	do sudo kill -INT $i; 
done 