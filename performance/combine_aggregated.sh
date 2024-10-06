for i in Trial_Out/*; 
	do 
	if [[ -d "$i" ]]; then 
		echo -e "$i\n";
		cat "$i/summary.log" 
	fi
done

