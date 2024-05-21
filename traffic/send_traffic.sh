#!/bin/bash
for i in $(./svc_res.sh | grep '^|' | tail -n +2 | sed 's/^|//g');
	do 
	SVC=$(echo $i | cut -d'|' -f 1);
	IF=$(echo $i | cut -d'|' -f 2); 
	FILE=$(ls | grep "$SVC")
	echo "$SVC @ $IF -> $FILE" 
	sudo tcpreplay -i "$IF" "$FILE"
done



