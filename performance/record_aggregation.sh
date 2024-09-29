for i in Trial_Out/*; 
	do 
	if [[ -d "$i" ]]; then 
		echo -e "$i\n";
		./analyse_folder.sh "$i" ;
	fi
done

