#!/bin/bash
sudo sh -c "bash -c \"docker run -t --rm --name rabbitmq -p 5673:5672 -p 15673:15672 -e RABBITMQ_DEFAULT_USER=ztrke2 -e RABBITMQ_DEFAULT_PASS=ztrke2 rabbitmq:3.12-management\"" &

sleep 20
source ../venv/bin/activate && python3 init_mq.py