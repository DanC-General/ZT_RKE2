FROM ubuntu:latest
RUN apt-get update && apt-get install -y openssh-server
# Configure SSH
RUN mkdir /var/run/sshd
RUN echo 'root:test' | chpasswd
#password for user login
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN adduser --disabled-password anonymous
RUN sed -i -re 's/^anonymous:[^:]+:/anonymous::/' /etc/passwd /etc/shadow
EXPOSE 22
# Start SSH server
CMD ["/usr/sbin/sshd", "-D"]