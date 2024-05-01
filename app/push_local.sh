#!/bin/bash
# for i in ./*/*.yaml; do 
#     # do echo $i; 
#     if [[ -z $(echo $i | grep 'k8s') ]]; then
#         echo "No kubernetes $i";
#         sudo docker build $i;
#     fi 
# done; 
./reg_init.sh
DIRS=("db" "ssh" "http")
for i in ${DIRS[@]}; do 
    echo "Directory $i"
    sudo docker build -t "$i" "./$i"
    sudo docker image tag "$i" "localhost:5000/$i"
    sudo docker push "localhost:5000/$i"
done
#docker run -dit -p 3000:22 ssh