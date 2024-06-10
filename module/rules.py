import os
import time
import subprocess
# class Subject:

# class Object: 
#     def __init__:
svc_list = dict()
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

def terminate_connection(pack):
    src_port = pack.sport
    targ_port = svc_list[pack.svc]
    print("Terminating connection on " + src_port + " <-> " + targ_port)
    output = subprocess.run(["./terminate.sh"]+[targ_port,src_port])

def get_lines(pipe): 
    # Check packet counts 
    with open(pipe, 'r') as f: 
        print("looping")
        count = 0
        while True: 
            data = f.readline()
            print(data)
            # Split the string into a list with the necessary 
            #   fields for class parsing.
            details = data.strip().split("|")
            pack = Packet(details)
            print(pack)  
            print(time.gmtime(int(pack.ts) / 1000000 )) 
            count = count + 1 
            if count % 11 ==0: 
                print("count 11")
                terminate_connection(pack)
                
def make_svcs(): 
    global svc_list
    command1 = ["./svc_res.sh"]
    command2 = ["grep", "'^|'"]  
    p1 = subprocess.Popen(command1, stdout=subprocess.PIPE)
    output = subprocess.check_output(('grep', '^-'), stdin=p1.stdout,universal_newlines=True)
    parsed = [x for x in list(map(lambda x:x.replace('-',''),output.split("\n"))) if x]
    print(parsed)
    for x in parsed: 
        arr = x.split(":")
        print(arr)
        svc_list[arr[0]] = arr[1]


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