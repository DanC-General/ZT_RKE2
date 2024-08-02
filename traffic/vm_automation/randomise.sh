#!/bin/bash
for i in ./*/normal/*.sh
    do 
    # ls "$i"
    deploy=$(echo "$i" | sed -E 's/\.\/(\w+).*/\1/g')
    echo "$deploy:$i"
    # echo $(("RANDOM" % 3))
done 
