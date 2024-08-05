#!/bin/bash

if [[ -z $(sudo docker ps -a | grep registry) ]]; then
    sudo docker run -d -p 5000:5000 --name registry registry:latest
else
    sudo docker start registry 
fi

if [[ -z $(sudo docker ps -a | grep rabbitmq | grep 15673) ]]; then 
    sudo sh -c "bash -c \"cd ../monitor/syscall-monitor && ./start;\"" &
fi