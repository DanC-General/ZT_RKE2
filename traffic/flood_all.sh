for i in $(./scripts/svc_res.sh | grep '^-' | sed 's/^-//');
	do 
	# sudo hping3 -S localhost -p $(echo $i | cut -d: -f 2); 
	sudo gnome-terminal -- sh -c "bash -c \"sudo hping3 -S localhost -p $(echo $i | cut -d: -f 2);bash\""

done 


