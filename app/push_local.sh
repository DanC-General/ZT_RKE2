#!/bin/bash
# for i in ./*/*.yaml; do 
#     # do echo $i; 
#     if [[ -z $(echo $i | grep 'k8s') ]]; then
#         echo "No kubernetes $i";
#         sudo docker build $i;
#     fi 
# done; 
./reg_init.sh
# DIRS=("db" "ssh" "http")
# for i in ${DIRS[@]}; do 
#     echo "Directory $i"
#     sudo docker build -t "$i" "./$i"
#     sudo docker image tag "$i" "localhost:5000/$i"
#     sudo docker push "localhost:5000/$i"
# done
# sudo docker build -t ssh "./ssh"
sudo docker compose build
sudo docker image tag app-ssh localhost:5000/ssh
sudo docker push localhost:5000/ssh

# sudo docker build -t http "./http/frontend"
sudo docker image tag app-http localhost:5000/http
sudo docker push localhost:5000/http
#docker run -dit -p 3000:22 ssh