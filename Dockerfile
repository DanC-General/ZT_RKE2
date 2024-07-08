FROM ubuntu:24.04
RUN apt update
RUN apt install libpcap-dev -y
RUN apt install tcpdump -y
RUN apt install tmux -y
RUN apt install python3 -y
RUN apt install make , iproute2 
COPY module /module 
COPY run_vm.sh run.sh
# CMD ["./run.sh"]