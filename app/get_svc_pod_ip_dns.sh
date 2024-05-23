#!/bin/bash
# Find user-defined services in the default namespace 
SERVICE_DETAILS=$(sudo kubectl get services -o=custom-columns=NAME:.metadata.name,PORTS:.spec.ports[*].port | tail -n +2 | grep -v '^kubernetes ' | tr -s [:space:])
MAPPINGS=()
# Uses internal ports, so should work for both clusterIP's and NodePorts.
for i in $(sudo kubectl get services -o=custom-columns=NAME:.metadata.name,PORTS:.spec.ports[*].port | tail -n +2 | grep -v '^kubernetes ' | tr -s [:space:] | tr ' ' '|') 
	do SVC_NAME=$(echo "$i" | cut -d'|' -f 1) 
	PORTS=$(echo "$i" | cut -d'|' -f 2)
	for i in $(echo "$PORTS" | tr ',' ' ')
		do 
		echo "Added map $SVC_NAME:$i"
		MAPPINGS+=( "$SVC_NAME:$i" )
	done
done
RULES=$(sudo iptables -t nat -L)
IF_DETAILS=$(ip a) 
SEARCH_STR="";
OUTPUT=""
for i in ${MAPPINGS[@]}; do
	IP=$(echo "$RULES" |  grep "$i" | grep all | grep -oE '([0-9]{1,4}\.){3}[0-9]{1,4}' | sort -u)
	POD_NAME=$(sudo kubectl get pods -o=custom-columns=NAME:.metadata.name,IP:.status.podIP | tr -s [:space:] | tail -n +2 | grep $IP | cut -d' ' -f 1)
	IF_NUM=$(sudo kubectl exec "$POD_NAME" -- cat /sys/class/net/eth0/iflink )
	IF_NAME=$(echo "$IF_DETAILS" | grep "^$IF_NUM" | cut -d':' -f 2 | cut -d'@' -f 1 | tr -d '[:space:]') 
	SVC=$(echo $i | cut -d':' -f 1)
	echo "Mapping service $SVC: $i --> $IP --> $POD_NAME --> $IF_NUM --> $IF_NAME"; 
	# echo "|$SVC|$IF_NAME"
	if [[ $OUTPUT == "" ]]; then
		OUTPUT="|$SVC|$IF_NAME"
	else
		OUTPUT="$OUTPUT"$'\n'"|$SVC|$IF_NAME"
	fi
	#if [ -z "$SEARCH_STR" ]; then 
	#	echo "Empty string"
	#	SEARCH_STR="$i"
	#else
	#	SEARCH_STR="$SEARCH_STR\|$i"
	#fi 
done
echo "|$(echo "$OUTPUT" | sort -u | wc -l)" 
for i in $(echo "$OUTPUT" | sort -u); do
	echo "$i"
done

# Find the resolutions of the services in ips. 
# sudo iptables -t nat -L  | grep "$SEARCH_STR" | grep all

