import os
import chardet
import re
import threading
import subprocess
from subprocess import CalledProcessError
from utils.DataStructs import Packet, PrioQ, StatTracker
from collections import deque
import queue
from Kitsune import Kitsune
import sys
import sched
from time import sleep, time
import json
sys.path.append("../syscall-monitor")
import msg_handler as rq
# sport:Connection -  should ocassionally wipe
s = sched.scheduler(time,sleep)
conn_dict = dict()
svc_dict = dict()
stat_dict = dict()
ml_dict = dict()
pod_cidr = ""
msg_q = queue.Queue()
# Need to split by deployment
subj_sysc_map = dict()
prev_subj = PrioQ()
terminated = dict()

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

def terminate_connection(ip,port):
    # print(host_det)
    print("Terminating connection on " , ip , " <-> " , port)
    output = subprocess.run(["../scripts/terminate.sh"]+[ip,port])

def handle_alert(syscall,alert_ts,log): 
    global subj_sysc_map
    # print("Recieved an alert!!")
    # print(item)
    log.write(syscall + str(alert_ts) + "\n")
    recency = 5
    # Change to use alert ts
    for subject in prev_subj.more_recent(alert_ts): 
        print("Adding to malicious", subject)
        # if subject not in subj_sysc_map: 
        #     subj_sysc_map[subject] = dict()
        # else: 
        #     # if "total" not in subj_sysc_map[subject]: 
        #     #     subj_sysc_map[subject]["total"] = 1 * recency
        subj_sysc_map[subject]["total"] += 1 * recency
        if syscall not in subj_sysc_map[subject]:
            subj_sysc_map[subject][syscall] = 1 * recency
        else:
            subj_sysc_map[subject][syscall] += 1 * recency
        # Update so next subject is less recent
        recency -= 2
    log.write(str(subj_sysc_map) + "\n")


def total_abnormal(): 
    total = 0
    for subject in subj_sysc_map: 
        if "total" in subj_sysc_map[subject]:
            total += subj_sysc_map[subject]["total"]
    return total

def get_lines(pipe): 
    global conn_dict
    global stat_dict
    global terminated
    global subj_sysc_map
    # Check packet counts 
    with open(pipe, 'r') as f: 
        print("looping")
        log = open("../logs/py.log",'w')
        count = 0
        while True: 
            # Read in data as bytes from pipe 
            #    - readline had encoding issues on other OSs
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
            orig_sip, orig_sport = pack.external_port(pod_cidr)
            get_connection(pack)
            log.write(str(pack) + "\n")

            # Update stored statistics
            stats = stat_dict[pack.svc]
            # log.write(pack)
            stats.enqueue(pack) 

            # Add subject to list of recent for tagging
            subject = pack.external_port(pod_cidr)[0]
            print("Current subject is ", subject)
            if subject not in subj_sysc_map: 
                subj_sysc_map[subject] = dict()
                print("Map did not contain ", subject)
            if "total" not in subj_sysc_map[subject]: 
                subj_sysc_map[subject]["total"] = 0
                print(subject, "did not contain total")

            if not prev_subj.contains(subject):
                print("APPENDING ", subject, "\n")
                prev_subj.add((pack.ts,subject))
                print(prev_subj)

            # Train relevant ML instance
            ml_dict[pack.svc].FE.packets.append(pack)
            rmse =  ml_dict[pack.svc].proc_next_packet()
            log.write("RMSE for " + pack.svc + str(ml_dict[pack.svc].FE.curPacketIndx) +  ":" + str(rmse) +"\n")

            # Extract message from queue if one exists
            #   - otherwise pass.
            cur_call = None
            while not msg_q.empty():
                # TODO Could alter this to retrieve all messages from the queue
                item = msg_q.get(block=False)
                print(item)
                cur_call = item[0]
                alert_time = item[1]
                handle_alert(cur_call,alert_time,log)
            # Evaluate system trust
            obj_trust = rmse
            subj_trust = -1
            total_ab_sys = total_abnormal()
            if subj_sysc_map[subject]["total"] > 0 and total_ab_sys > 0 :
                print("Set subject trust to ", subj_sysc_map[subject]["total"],"/",total_ab_sys," = ",int(subj_sysc_map[subject]["total"])/int(total_ab_sys))
                subj_trust = int(subj_sysc_map[subject]["total"])/int(total_ab_sys)
                log.write("Object trust: " + str(obj_trust) + ". Subject trust for " + subject + ": " + str(subj_trust) + "\n")
                if cur_call in subj_sysc_map: 
                    if subj_sysc_map[subject][cur_call] != 1: 
                        print("Repeat syscall ",cur_call, ", skipping.")
                        subj_trust = -1
            else: 
                log.write("Object trust: " + str(obj_trust) + ". Subject fully trusted\n")
            subj_sysc_map[subject]["trust"] = subj_trust
            log.write(str(subj_sysc_map))

            # Act on system trust
            if obj_trust > 100 or subj_trust > 0.8: 
                # print("Abnormal RMSE: ",rmse)
                log.write("ALERTED! Object: " + str(obj_trust) + ".Subject: " + str(subj_trust) + ".\n")
                if orig_sip not in terminated:
                    terminated[orig_sip] = dict()
                if orig_sport not in terminated[orig_sip]: 
                    log.write("Terminated connection.")
                    # Dummy value for termination
                    terminated[orig_sip][orig_sport] = 0
                    terminate_connection(orig_sip,orig_sport)

            log.flush()

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
    # KitNET params - initalisation from Kitsune:
    maxAE = 10 #maximum size for any autoencoder in the ensemble layer
    FMgrace = 100 #the number of instances taken to learn the feature mapping (the ensemble's architecture)
    ADgrace = 1000 #the number of instances used to train the anomaly detector (ensemble itself)

    for x in parsed: 
        arr = x.split(":")
        # print(arr)
        
        svc_dict[arr[0]] = arr[1]
        svc_dict[arr[0]] = Service()
        stat_dict[arr[0]] = StatTracker()
        ml_dict[arr[0]] = Kitsune(None,None,maxAE,FMgrace,ADgrace)
    # print(stat_dict)
    # print(svc_dict)
class Service: 
    def __init__(self,maxAE,FMgrace,ADgrace): 
        self.subj_sysc_map = dict()
        self.prev_subj = PrioQ()
        self.terminated = dict()
        self.s = sched.scheduler(time,sleep)
        self.ml = Kitsune(None,None,maxAE,FMgrace,ADgrace)
        self.stats = StatTracker()
    
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
            time_s = str(int(float(fields["output_fields"]["evt.time"]) / 1000000000))
            msg_q.put([fields["output_fields"]["syscall.type"],time_s])
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

def adjust_trust(): 
    global subj_sysc_map
    for subject in subj_sysc_map:
        subj_sysc_map[subject]["trust"] += 0.5 
        if subj_sysc_map[subject]["trust"] >= 1:
            subj_sysc_map[subject]["trust"] = 1

    print("Increased trusts at ", time())

def repeat(): 
    # TODO Update for hour
    s.enter(3600,1,adjust_trust)
    s.enter(3600,1,repeat)

def run_sched():
    repeat()
    s.run()

def main(): 
    # Communication with scrape.c occurs
    #   through the "traffic_data" pipe. 
    threading.Thread(target=retrieve).start()
    # Start the process to update subject trusts every hour. 
    threading.Thread(target=run_sched).start()
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
