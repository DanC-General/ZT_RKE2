#!/bin/bash

<<description

Resend captured traffic from pcaps across interfaces. 
Requires a pcap file with a name containing the service name. 
That file will be re-sent using tcpreplay over the relevant 
	service interface.

description

for i in $(./svc_res.sh | grep '^|' | tail -n +2 | sed 's/^|//g');
	do 
	SVC=$(echo $i | cut -d'|' -f 1);
	IF=$(echo $i | cut -d'|' -f 2); 
	FILE=$(ls | grep "$SVC")
	echo "$SVC @ $IF -> $FILE" 
	sudo tcpreplay -i "$IF" "$FILE"
done



