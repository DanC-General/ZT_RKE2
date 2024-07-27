import os
import chardet
import re
import threading
import subprocess
from subprocess import CalledProcessError
from Packet import Packet
from collections import deque
import queue
from netaddr import IPNetwork, IPAddress
from Kitsune import Kitsune
import sys
from time import sleep
import json
sys.path.append("../syscall-monitor")
import msg_handler as rq
# sport:Connection -  should ocassionally wipe
conn_dict = dict()
svc_dict = dict()
stat_dict = dict()
ml_dict = dict()
pod_cidr = ""
msg_q = queue.Queue()
subj_sysc_map = dict()
total_ab_sys = 0
prev_subj = deque(maxlen=3)
class Conn_Detail:
    def __init__(self,arr): 
        self.sip = arr[0]
        self.dip = arr[1]
        self.sport = arr[2]
        self.dport = arr[3]
    def __str__(self):
        ret = ""
        for k in vars(self): 
            ret += k+"->"+vars(self)[k]+" | "
        return ret

class Connection: 
    # Stores external mappings for conntrack 
    # tcp      6 82684 ESTABLISHED src=192.168.122.10 dst=10.43.238.254 sport=51682 dport=8003 src=10.42.0.62 dst=10.1.1.243 sport=22 dport=59424 [ASSURED] mark=0 use=1
    def __init__(self,original,translated): 
        self.original = original
        self.translated = translated
    def __str__(self):
        ret = ""
        for k in vars(self): 
            ret += k+"->"+str(vars(self)[k])+" | "
        return ret
    
# Stores statistics for the last 100 packets
class StatTracker: 

    def __init__(self): 
        self.packets = deque(maxlen=100)
        self.mean_size = 0

    def enqueue(self,pack: Packet): 
        sz = int(pack.size)
        # self.packets.append([datetime.datetime.fromtimestamp(int(pack.ts)),int(pack.size)])
        self.packets.append([float(pack.ts), sz])
        self._update_stats(pack)
        
    def _update_stats(self,pack:Packet): 
        sz = int(pack.size)
        if self.mean_size == 0: 
            self.mean_size = sz
        else: 
            prev_mean = self.mean_size
            self.mean_size = ((prev_mean * (len(self.packets) - 1)) + sz )/ (len(self.packets))

    def time_diff(self):
        change = self.packets[-1][0] - self.packets[0][0]
        return change , len(self.packets)
    
def parse_conntrack(conn_str,packet):
# tcp      6 82684 ESTABLISHED src=192.168.122.10 dst=10.43.238.254 sport=51682 dport=8003 src=10.42.0.62 dst=10.1.1.243 sport=22 dport=59424 [ASSURED] mark=0 use=1
    # print("SEARCHING FOR ", conn_str)
    patterns = ["src","dst","sport","dport"]
    raw_det = list()
    new_details = list()
    for pattern in patterns: 
        cur_pat = pattern +r"=(\S*) "
        res = re.findall( cur_pat , conn_str)
        raw_det.append(res)
        # print(res)
    if packet.external_port(pod_cidr)[0] == raw_det[1][1]:
        # External ip is first value - new values should be first values
        if packet.external_port(pod_cidr)[0] == packet.sip: 
            packet.sip = raw_det[0][0]
            packet.sport = raw_det[2][0]
        else: 
            packet.dip = raw_det[0][0]
            packet.dport = raw_det[2][0]
        return packet        
        pass
    # print("result is ", raw_det)
    return conn_str + "\n"

def get_connection(pack): 
    command1 = ["conntrack","-L"]
    command2 = ["grep",pack.external_port(pod_cidr)[0]+".*"+pack.external_port(pod_cidr)[1]]  
    # try: 
    p1 = subprocess.Popen(command1, stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    output = subprocess.run(command2, stdin=p1.stdout,stdout=subprocess.PIPE,universal_newlines=True,check=False).stdout
    # print("OUTPUT is " + output)
    if output is None or output == "": 
        return pack
    # except CalledProcessError: 
    #     pass
    return parse_conntrack(output,pack)

def terminate_connection(pack):
    host_det = pack.external_port(pod_cidr)
    # print(host_det)
    print("Terminating connection on " , host_det[0] , " <-> " , host_det[1])
    output = subprocess.run(["../scripts/terminate.sh"]+[host_det[0],host_det[1]])

def handle_alert(item,log): 
    global total_ab_sys
    global subj_sysc_map
    total_ab_sys += 1
    # print("Recieved an alert!!")
    # print(item)
    log.write(str(item) + "\n")
    for subject in prev_subj: 
        if subject not in subj_sysc_map: 
            subj_sysc_map[subject] = 1
        else: 
            subj_sysc_map[subject] += 1

    log.write(str(subj_sysc_map) + "\n")


def get_lines(pipe): 
    global conn_dict
    global stat_dict
    # Check packet counts 
    with open(pipe, 'r') as f: 
        print("looping")
        log = open("../logs/py.log",'w')
        count = 0
        while True: 
            if not msg_q.empty():
                handle_alert(msg_q.get(block=False),log)
            data = ""
            while True: 
                cur = f.read(1)
                data += cur
                if cur == '\n': 
                    break 
            # Split the string into a list with the necessary 
            #   fields for class parsing.
            log.write(data + "\n")
            details = data.strip().split("|")
            if len(details) != 10: 
                continue
            pack = Packet(details)
            # print("PACK BEFORE IS",pack)
            get_connection(pack)
            # print("PACK AFTER IS",pack)
            log.write(str(pack) + "\n")
            # log.write(str(packet))
            stats = stat_dict[pack.svc]
            # log.write(pack)
            stats.enqueue(pack) 
            subject = pack.external_port(pod_cidr)[0]
            if subject not in prev_subj:
                print("APPENDING ", subject, ", ",total_ab_sys, " total syscalls.\n")
                prev_subj.append(subject)
    
            ml_dict[pack.svc].FE.packets.append(pack)
            rmse =  ml_dict[pack.svc].proc_next_packet()
            log.write("RMSE for " + pack.svc + str(ml_dict[pack.svc].FE.curPacketIndx) +  ":" + str(rmse) +"\n")
            if rmse > 100: 
                # print("Abnormal RMSE: ",rmse)
                terminate_connection(pack)

        log.close()
def make_svcs(): 
    global svc_dict
    global stat_dict
    global ml_dict
    command1 = ["../scripts/svc_res.sh"]
    p1 = subprocess.Popen(command1, stdout=subprocess.PIPE)
    output = subprocess.check_output(('grep', '^-'), stdin=p1.stdout,universal_newlines=True)
    parsed = [x for x in list(map(lambda x:x.replace('-',''),output.split("\n"))) if x]
    # log.write(parsed)
    # KitNET params:
    maxAE = 10 #maximum size for any autoencoder in the ensemble layer
    FMgrace = 100 #the number of instances taken to learn the feature mapping (the ensemble's architecture)
    ADgrace = 1000 #the number of instances used to train the anomaly detector (ensemble itself)

    for x in parsed: 
        arr = x.split(":")
        # print(arr)
        svc_dict[arr[0]] = arr[1]
        stat_dict[arr[0]] = StatTracker()
        ml_dict[arr[0]] = Kitsune(None,None,maxAE,FMgrace,ADgrace)
    # print(stat_dict)
    # print(svc_dict)

def get_cidr(): 
    global pod_cidr
    pod_cidr = subprocess.check_output((
        "sudo","kubectl","get","nodes","-o" ,
        "jsonpath={.items[*].spec.podCIDR}")).decode()

def on_recv(channel,method,properties,body): 
    global prev_time
    fields = json.loads(body.decode())
    # print(json.loads(body.decode()))
    try: 
        # print("Image: ", fields["output_fields"]["container.image.repository"], " pod name: ", fields["output_fields"]["k8s.pod.name"],fields["output_fields"]["container.name"],fields["rule"])
        if (fields["output_fields"]["container.name"] in fields["rule"]): 
            # print("Changing runtime...")
            # Don't need nanosecond precision
            # print(fields)
            msg_q.put(fields)
            time_s = str(int(float(fields["output_fields"]["evt.time"]) / 1000000000))
            # print(time_s)
            # print("Container up for " , float(fields["output_fields"]["container.duration"])  / 1000000000 )
            # subprocess.run("./random_script.sh" + fields["output_fields"]["container.image.repository"] + " " + fields["output_fields"]["k8s.pod.name"] 
            #                + " " + time_s + " " + str(fields["output_fields"]["proc.pid"]),shell=True)
    except KeyError: 
        return 
    
def retrieve(): 
    temp = rq.AMQPConnection()
    print("Formed AMQP Connection...")
    sleep(10)
    while(1):
        temp.channel.basic_consume(queue="events",on_message_callback=on_recv,auto_ack=True)
        temp.channel.start_consuming()
    temp.connection.close()
    
def main(): 
    # Communication with scrape.c occurs
    #   through the "traffic_data" pipe. 
    threading.Thread(target=retrieve).start()
    pipe = "../traffic_data"
    while not os.path.exists(pipe):
        pass  
    get_cidr()
    make_svcs()
    # print(svc_dict)
    get_lines(pipe)        
    os.unlink(pipe)  

if __name__ == "__main__":
    print(os.getcwd())
    main()
