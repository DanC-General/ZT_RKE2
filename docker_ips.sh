#!/bin/bash
for i in $(docker container ls | head -n 4 | tail -n 3 | cut -d" " -f 1); 
    do echo "$(docker container ls | head -n 4 | tail -n 3 | grep $i | tr -s ' ' | cut -d" " -f 2) : $i : $(docker inspect $i | grep -i 'networkmode\|\"ipaddress')"
done