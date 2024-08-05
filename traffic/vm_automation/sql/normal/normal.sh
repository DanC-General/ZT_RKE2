#!/bin/bash
mysql -h "$IP" -P 30003 --protocol=tcp -u root -ppassword_123! << EOF
use test;
do sleep ($RANDOM % 11); 
show tables;
do sleep ($RANDOM % 11); 
SELECT * FROM users; 
do sleep ($RANDOM % 11); 
insert into users(username,password) values ("comp","res");
EOF 