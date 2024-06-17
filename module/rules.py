import os
import time
import subprocess
import re
# sport:Connection -  should ocassionally wipe
conn_dict = dict()
svc_dict = dict()
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

class Packet: 
    # Initialise the variables from the 
    #   packet list.
    def __init__(self,props): 
        self.svc = props[0]
        self.smac = props[1]
        self.dmac = props[2]
        self.sip = props[3]
        self.dip = props[4]
        self.sport = props[5]
        self.dport = props[6]
        self.ts = props[7]
        self.size = props[8]
    def __str__(self):
        ret = ""
        for k in vars(self): 
            ret += k+"->"+vars(self)[k]+" | "
        return ret

def get_connection(svc,sport): 
    command1 = ["conntrack","-L"]
    command2 = ["grep",svc+".*"+sport]  
    p1 = subprocess.Popen(command1, stdout=subprocess.PIPE)
    output = subprocess.check_output(command2, stdin=p1.stdout,universal_newlines=True)
    return output

def terminate_connection(pack):
    src_port = pack.sport
    targ_port = svc_dict[pack.svc]
    print("Terminating connection on " + src_port + " <-> " + targ_port)
    output = subprocess.run(["./terminate.sh"]+[targ_port,src_port])

def get_lines(pipe): 
    global conn_dict
    # Check packet counts 
    with open(pipe, 'r') as f: 
        print("looping")
        count = 0
        while True: 
            data = f.readline()
            # print(data)
            # Split the string into a list with the necessary 
            #   fields for class parsing.
            details = data.strip().split("|")
            pack = Packet(details)
            # print(time.gmtime(int(pack.ts) / 1000000 )) 
            count = count + 1 
            # if count % 11 ==0: 
            #     print("count 11")
            #     terminate_connection(pack)
            # Find original ip if external
            # print(pack)  
            if pack.sip == "10.1.1.243" or pack.dip == "10.1.1.243": 
                sc = pack.sip == "10.1.1.243" 
                if sc: 
                    prt = pack.sport
                    ip = pack.sip
                else:
                    prt = pack.dport
                    ip = pack.dip
                    
                if prt not in conn_dict: 
                    # print("PORT ",prt)
                    # print("Finding connection",svc_dict[pack.svc], " , ",prt)
                    res = get_connection(svc_dict[pack.svc],prt)
                    kw = ["src","dst","sport","dport"] 
                    orig = list()
                    new = list()
                    for i in kw: 
                        matches = re.finditer(i + r"=([0-9\.]*)",res)
                        count = 0
                        for match in matches:
                            count += 1
                            if count == 1:
                                orig.append(match.group(1))
                            if count == 2:
                                new.append(match.group(1))
                    conn_dict[new[3]] = Connection(Conn_Detail(orig),Conn_Detail(new))
                    # print(res)
                    # print(orig, "-->", new)
                if sc: 
                    pack.sip = conn_dict[pack.sport].original.sip
                    pack.sport = conn_dict[pack.sport].original.sport
                else: 
                    pack.dip = conn_dict[pack.dport].original.sip
                    pack.dport = conn_dict[pack.dport].original.sport
                # print("__ New Pack __")
                print(pack)
                # print([f"Key: {key}, Value: {value}" for key, value in conn_dict.items()])
                    
                
def make_svcs(): 
    global svc_dict
    command1 = ["./svc_res.sh"]
    command2 = ["grep", "'^|'"]  
    p1 = subprocess.Popen(command1, stdout=subprocess.PIPE)
    output = subprocess.check_output(('grep', '^-'), stdin=p1.stdout,universal_newlines=True)
    parsed = [x for x in list(map(lambda x:x.replace('-',''),output.split("\n"))) if x]
    print(parsed)
    for x in parsed: 
        arr = x.split(":")
        print(arr)
        svc_dict[arr[0]] = arr[1]


def main(): 
    # Communication with scrape.c occurs
    #   through the "traffic_data" pipe. 
    pipe = "traffic_data"
    while not os.path.exists(pipe):
        pass  
    make_svcs()
    get_lines(pipe)        
    os.unlink(pipe)  

if __name__=="__main__":
    main()