import os
import chardet
import re
import subprocess
from subprocess import CalledProcessError
from Packet import Packet
from collections import deque
from netaddr import IPNetwork, IPAddress
from Kitsune import Kitsune

# sport:Connection -  should ocassionally wipe
conn_dict = dict()
svc_dict = dict()
stat_dict = dict()
ml_dict = dict()
pod_cidr = ""
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
    print("SEARCHING FOR ", conn_str)
    patterns = ["src","dst","sport","dport"]
    raw_det = list()
    new_details = list()
    for pattern in patterns: 
        cur_pat = pattern +r"=(\S*) "
        res = re.findall( cur_pat , conn_str)
        raw_det.append(res)
        print(res)
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
    print("result is ", raw_det)
    return conn_str + "\n"

def get_connection(pack): 

    command1 = ["conntrack","-L"]
    command2 = ["grep",pack.external_port(pod_cidr)[0]+".*"+pack.external_port(pod_cidr)[1]]  
    # try: 
    p1 = subprocess.Popen(command1, stdout=subprocess.PIPE)
    output = subprocess.run(command2, stdin=p1.stdout,stdout=subprocess.PIPE,universal_newlines=True,check=False).stdout
    print("OUTPUT is " + output)
    if output is None or output == "": 
        return pack
    # except CalledProcessError: 
    #     pass
    return parse_conntrack(output,pack)

def terminate_connection(pack):
    host_det = pack.external_port(pod_cidr)
    print(host_det)
    print("Terminating connection on " , host_det[0] , " <-> " , host_det[1])
    output = subprocess.run(["../scripts/terminate.sh"]+[host_det[0],host_det[1]])

def get_lines(pipe): 
    global conn_dict
    global stat_dict
    # Check packet counts 
    with open(pipe, 'r') as f: 
        print("looping")
        log = open("../logs/py.log",'w')
        count = 0
        while True: 
            # data = f.readline()
            data = ""
            while True: 
                cur = f.read(1)
                data += cur
                if cur == '\n': 
                    break 
            # result = chardet.detect(data)
            # encoding = result['encoding']

            # if encoding:
            #     print("Detected encoding:", encoding)
            # else:
            #     print("Encoding detection failed.")

            # print(data)
            # Split the string into a list with the necessary 
            #   fields for class parsing.
            log.write(data + "\n")
            details = data.strip().split("|")
            if len(details) != 10: 
                continue
            pack = Packet(details)
            packet = get_connection(pack)
            log.write(str(pack) + "\n")
            # log.write(str(packet))
            stats = stat_dict[pack.svc]
            # log.write(pack)
            stats.enqueue(pack) 
            # print(pack.external_port(pod_cidr))
            # print(stats)
            # print(stats, stats.time_diff()[0], stats.mean_size)
            # print(time.gmtime(int(pack.ts) / 1000000 )) 
            # print(pack.return_ml_data(stat_dict))     
            ml_dict[pack.svc].FE.packets.append(pack)
            # print("Kitsune event ", pack.svc)
            rmse =  ml_dict[pack.svc].proc_next_packet()
            # print("RMSE for " , pack.svc , ml_dict[pack.svc].FE.curPacketIndx, ":" , rmse)
            log.write("RMSE for " + pack.svc + str(ml_dict[pack.svc].FE.curPacketIndx) +  ":" + str(rmse) +"\n")
            if rmse > 100: 
                # print("Abnormal RMSE: ",rmse)
                terminate_connection(pack)
            # count = count + 1 
            # if count % 100 ==0: 
            #     print("count 100")
                # terminate_connection(pack)
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

def main(): 
    # Communication with scrape.c occurs
    #   through the "traffic_data" pipe. 
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


# class Packet: 
#     # Initialise the variables from the 
#     #   packet list.
#     def __init__(self,props): 
#         self.svc = props[0]
#         self.smac = props[1]
#         self.dmac = props[2]
#         self.sip = props[3]
#         self.dip = props[4]
#         self.sport = props[5]
#         self.dport = props[6]
#         self.ts = props[7]
#         self.size = props[8]
#         self.flags = int(props[9])

#     def __str__(self):
#         ret = ""
#         for k in vars(self): 
#             ret += k+"->"+str(vars(self)[k])+" | "
#         return ret
    
#     def get_tcp_flags(self):
#         """
#         This function takes a byte value representing the TCP flags field and returns a list of the set flags.

#         Args:
#             flags_byte: A byte value representing the TCP flags field.

#         Returns:
#             A list of strings representing the set TCP flags (e.g., ["SYN", "ACK"]).
#         """

#         # Flag names and their corresponding bit positions
#         flag_names = {
#             1: "URG",
#             2: "SYN",
#             4: "ACK",
#             8: "PSH",
#             16: "RST",
#             32: "FIN",
#         }
#         results = [1,2,4,8,16,32]
#         set_flags = []
#         for i,val in enumerate(results):
#             # Check if the bit is set (value 1) using bitwise AND
#             if self.flags & val:
#                 set_flags.append(flag_names[val])
#                 results[i] = 1
#             else:
#                 results[i] = 0
#         return set_flags,results

#     def return_ml_data(self):
#         _, flags = self.get_tcp_flags()
#         cur_stats = stat_dict[self.svc]
#         return [self.ts,self.size, self.svc,self.sip,self.dip,self.sport,
#                 self.dport] + flags + [cur_stats.mean_size, cur_stats.time_diff()[0]]
    
#     def external_port(self): 
#         """ 
#         Returns the port used in the external communication.
#         If the source IP is the pods', return destination port 
#             and vice versa. 
#         """
#         if IPAddress(self.sip) in IPNetwork(pod_cidr):
#             print("Source is pod")
#             return self.dip, self.dport
#         elif IPAddress(self.dip) in IPNetwork(pod_cidr):
#             print("Dest is pod")
#             return self.sip, self.sport
#         else: 
#             print("Neither is pod")
#             return -1