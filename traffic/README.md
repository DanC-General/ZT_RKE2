# Overview 

This folder includes files necessary to the traffic and packet 
handling for the module. This includes packet captures (.pcap 
extension) and shell scripts used to replicate the captures over 
relevant interfaces. 

## Structure

* {SVC}*.pcap 

    - Packet captures, which will be replayed over the interface 
    appropriate to the relevant service {SVC}. 

* svc_res.sh

    - Links back to the /app script mapping service names to the 
    interface names of their underlying pods. 

* send_traffic.sh 

    - Script that sends the packets in the pcap files over the relevant 
    interfaces. 



Make new vms 
Assign static addresses 
Change from nat to bridge 
Create a new bridge
