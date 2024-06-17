# sudo apt install mysql-client
mysql -h 10.43.132.9 -u root -ppassword_123! << EOF
exit 
EOF
sshpass -p "test" ssh -o StrictHostKeyChecking=no -p 8003 root@10.43.238.254 "ls"
curl 10.43.177.136:93

