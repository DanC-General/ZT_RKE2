#read -p "Would you like to back up your current traffic_out and sorted_out files? (y/N)" back
#if [ "$back" == 'y' ]; then
#	echo "Backing up..." 
#	mv $FSORT back_s.txt 
#	mv $FRAW back_t.txt
#	mv $FOUT back_c.txt
#fi 
stty -echoctl
declare -A name_maps
cmd_out="$({ sudo kubectl get pods -A -o wide | tr -s ' ' | sed 's/ \((.*)\)//g'| tail -n +2 | cut -d" " -f 2,7 && sudo kubectl get svc -o wide | tr -s ' ' | sed 's/ \((.*)\)//g'| tail -n +2 | cut -d" " -f 1,3 ;} | tr [:space:] ' ')"
DIR="./out"
if [ ! -d "$DIR" ]; then
	mkdir "$DIR"
fi 
TIME=$(date "+%m_%d_%H-%M-%S")
FRAW="$DIR/raw_out_$TIME.txt"
FSORT="$DIR/sorted_out_$TIME.txt"
FOUT="$DIR/counts_out_$TIME.txt"

# echo "cmd is $cmd_out"
IFS=' ' read -r -a NAME_ARR <<< "$cmd_out"
#"
# echo "Name arr is $NAME_ARR"
for i in ${!NAME_ARR[@]}; do 
	# echo "Element $i is ${NAME_ARR[$i]}"  
	if [[ $((i % 2)) -eq 1 ]]; then 
		name_maps["${NAME_ARR[$i]}"]="${NAME_ARR[$((i-1))]}"
		# echo "$i: SET ${NAME_ARR[$i]} to ${NAME_ARR[$((i-1))]}"
	fi
done
echo $name_maps
fin(){ 
	echo "Finalising..." 
	#cat $FRAW | cut -d" " -f 5,6,7,8 | tr " " "\n" | sort -u | cut -d"." -f 1,2,3,4 | sort -u | grep -P "^[\dl]" > $FSORT
	cat $FRAW | tr " " "\n" | sed 's/:$//g' | sort -u | cut -d"." -f 1,2,3,4 | sort -u | grep -P "^[\dl]" > $FSORT
	echo "     IP     : HOSTNAME : COUNT  " > $FOUT
	for i in $(cat $FSORT); do 
		if [[ $i =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || $i =~ localhost\.[0-9]+ ]]; then
			echo -n "$i : " >> $FOUT; 
			TEMP="${name_maps[$i]}" 
			if [[ -z $TEMP ]]; then
				TEMP="<Unknown>" 
			fi
			echo -n "$TEMP : " >> $FOUT
			cat $FRAW | grep $i | wc -l >> $FOUT;
		fi
	done
	FORMAT=`(head -n 1 $FOUT && tail -n +2 $FOUT | sort -k 5 -n) | column -t`

	echo "$FORMAT" > $FOUT
}

sudo tcpdump -i any > $FRAW
fin  
