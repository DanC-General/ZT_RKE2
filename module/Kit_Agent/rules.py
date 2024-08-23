import os
import re
import threading
import subprocess
from utils.DataStructs import Packet
from utils.Service import Service
from utils.FuzzyLogic import RRule
import queue
import sys
import sched
from time import sleep, time
import json
sys.path.append("../syscall-monitor")
import msg_handler as rq
# sport:Connection -  should ocassionally wipe
s = sched.scheduler(time,sleep)
msg_q = queue.Queue()
Rfuzz = RRule()
svc_dict = dict()
pod_cidr = ""


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

def get_lines(pipe): 
    global svc_dict
    # Check packet counts 
    with open(pipe, 'r') as f: 
        print("looping")
        log = open("../logs/py.log",'w')
        count = 0
        while True: 
            # Read in data as bytes from pipe 
            #    - readline had encoding issues on other OSs
            # data = ""
            # while True: 
            #     cur = f.read(1)
            #     data += cur
            #     if cur == '\n': 
            #         break 
            data = f.readline()
            # Split the string into a list with the necessary 
            #   fields for class parsing.
            # log.write(data + "\n")
            details = data.strip().split("|")
            if len(details) != 10: 
                continue
            pack = Packet(details)
            # print("Packet",pack.ts,"general time",time())
            orig_sip, orig_sport = pack.external_port(pod_cidr)
            get_connection(pack)
            # log.write(str(pack) + "\n")
            # log.write(str(pack.ts) + "\n")

            cur_svc = (svc_dict[pack.svc])
            cur_svc.count += 1
            cur_svc.log = log

            # Update stored statistics
            cur_svc.stats.enqueue(pack)

            # Train relevant ML instance
            cur_svc.ml.FE.packets.append(pack)
            rmse =  cur_svc.ml.proc_next_packet()
            # log.write("RMSE for " + pack.svc + str(cur_svc.ml.FE.curPacketIndx) +  ":" + str(rmse) +"\n")
            
            # Add subject to list of recent for tagging
            subject = pack.external_port(pod_cidr)[0]
            cur_svc.add_recent(subject,pack.ts)

            # Extract message from queue if one exists
            #   - otherwise pass.
            while not msg_q.empty():
                # TODO Could alter this to retrieve all messages from the queue
                item = msg_q.get(block=False)
                # print(item)
                cur_call = item[0]
                alert_time = item[1]
                # New subject trusts are made for the relevant subjects here
                cur_svc.handle_alert(cur_call,alert_time)
            # Evaluate system trust
            obj_trust = rmse
            # Clamp RMSE for fuzzy logic input
            if obj_trust > 1: 
                obj_trust = 1

            subj_trust = cur_svc.subject_trust(subject)
            # log.write(cur_svc.name + str(cur_svc.subj_sysc_map) + "\n")
            # Act on overall request trust
            # print(obj_trust,"vs",subj_trust)
            req_trust = Rfuzz.simulate(obj_trust,subj_trust,log)
            # log.write("Subject trust " + str(subj_trust) + ", Object trust " +
            #           str(obj_trust) + "--> ReqTrust " + str(req_trust) + "\n")
            if req_trust < 5: 
                cur_svc.terminate(orig_sip,orig_sport,log)
            log.flush()

        log.close()
def make_svcs(): 
    global svc_dict
    # global stat_dict
    # global ml_dict
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
        svc_dict[arr[0]] = Service(maxAE,FMgrace,ADgrace,arr[0],arr[1])

def get_cidr(): 
    global pod_cidr
    pod_cidr = subprocess.check_output((
        "sudo","kubectl","get","nodes","-o" ,
        "jsonpath={.items[*].spec.podCIDR}")).decode()

def on_recv(channel,method,properties,body): 
    # global prev_time
    fields = json.loads(body.decode())
    # print(fields)
    try: 
        if (fields["output_fields"]["container.name"] in fields["rule"]): 
            # Don't need nanosecond precision
            # time_s = str(int(float(fields["output_fields"]["evt.time"]) / 1000000000))
            msg_q.put([fields["output_fields"]["syscall.type"],fields["output_fields"]["evt.rawtime.s"]])
    except KeyError: 
        return 
    
def retrieve(): 
    temp = rq.AMQPConnection()
    print("Formed AMQP Connection...")
    # sleep(10)
    while(1):
        print("Consuming")
        temp.channel.basic_consume(queue="events",on_message_callback=on_recv,auto_ack=True)
        temp.channel.start_consuming()
    temp.connection.close()

def adjust_trust(): 
    # global subj_sysc_map
    global svc_dict
    for svc in svc_dict:
        sysc_map = (svc_dict[svc]).subj_sysc_map
        for subject in sysc_map:
            sysc_map[subject]["trust"] += 0.5 
            if sysc_map[subject]["trust"] >= 1:
                sysc_map[subject]["trust"] = 1

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
    # maxAE = 10 #maximum size for any autoencoder in the ensemble layer
    # FMgrace = 100 #the number of instances taken to learn the feature mapping (the ensemble's architecture)
    # ADgrace = 1000 #the number of instances used to train the anomaly detector (ensemble itself)
    # threading.Thread(target=retrieve).start()
    # tst= Service(maxAE,FMgrace,ADgrace,"test","123")
    # while True:
    #     if not msg_q.empty():
    #         a = msg_q.get()
    #         print("recv alert",a,"at",time())

    # t1 = tst.prev_subj
    # t1.more_recent(10.4)
    # t1.add([20.01,"subj2"])
    # t1.more_recent(20.2)
    # t1.add([30.102,"subj1"])
    # t1.add([33.47,"subj2"])
    # t1.more_recent(35.102)
    # t1.add([33.47,"subj3"])
    # t1.add([38.47,"subj4"])
    # t1.add([35.47,"subj5"])
    # t1.add([36.47,"subj7"])
    # t1.more_recent(40.1)

    # t1.more_recent(20.2)
