# ZT_RKE2
Repository of supporting code for Honours project. 

# Building 

## Install Docker 

[Here](https://docs.docker.com/engine/install/ubuntu/)

## Build images

`docker-compose -f up app/docker-compose.yaml`


## Install K8S 
Run rke2_install.sh

## Install kompose 
https://github.com/kubernetes/kompose

`curl -L https://github.com/kubernetes/kompose/releases/download/v1.33.0/kompose-linux-amd64 -o kompose`
`chmod +x kompose`
`sudo mv ./kompose /usr/local/bin/kompose`

Then need to fix errors on live - service names wrong 
Should just need to change '_' in Service names to '-' 

## Install libpcap libraries

`sudo apt-get install libpcap-dev` 

# Other installs 

sudo apt install tcpreplay 

sudo apt install gnome-terminal

