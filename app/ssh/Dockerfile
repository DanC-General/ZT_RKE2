FROM ubuntu:latest
RUN apt-get update && apt-get install -y openssh-server
# Configure SSH
RUN mkdir /var/run/sshd
RUN echo 'root:test' | chpasswd
#password for user login
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN adduser --disabled-password anonymous
RUN sed -i -re 's/^anonymous:[^:]+:/anonymous::/' /etc/passwd /etc/shadow
COPY ./test_keys ~/.ssh/
COPY ./exploits /var/run/sshd/exploits
RUN cat ~/.ssh/id_rsa.pub | tee -a ~/.ssh/known_hosts
RUN apt install gcc -y
RUN gcc -pthread /var/run/sshd/exploits/dirty.c -o /var/run/sshd/exploits/dirty
RUN echo "no test" > /var/run/sshd/exploits/foo 
RUN chmod 0404 /var/run/sshd/exploits/foo 
# EXPOSE 22
# Start SSH server
CMD ["/usr/sbin/sshd", "-D"]