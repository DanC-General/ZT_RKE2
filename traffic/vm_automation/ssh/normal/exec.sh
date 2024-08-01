# Execute a script
sshpass -p "test" ssh -o StrictHostKeyChecking=no -p 30002 root@"$IP" " 
echo "echo \"Hello World\"; cat *" >> echo_all.sh;
sleep $(RANDOM % 11); 
chmod +x echo_all.sh;
sleep $(RANDOM % 11); 
./echo_all.sh
"