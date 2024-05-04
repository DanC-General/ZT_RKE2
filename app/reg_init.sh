#!/bin/bash
if [[ -z $(sudo docker ps -a | grep registry) ]]; then
    sudo docker run -d -p 5000:5000 --name registry registry:latest
else
    sudo docker start registry 