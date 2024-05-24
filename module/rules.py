import os
import time
class Packet: 
    def __init__(self,props): 
        self.svc = props[0]
        self.smac = props[1]
        self.dmac = props[2]
        self.sip = props[3]
        self.dip = props[4]
        self.ts = props[5]
    def __str__(self):
        ret = ""
        for k in vars(self): 
            ret += k+"->"+vars(self)[k]+" | "
        return ret
        
def get_lines(pipe): 
    # Check packet counts 
    with open(pipe, 'r') as f: 
        print("looping")
        while True: 
            data = f.readline()
            details = data.strip().split("|")
            print(Packet(details))       

def main(): 
    pipe = "traffic_data"
    while not os.path.exists(pipe):
        pass  
    get_lines(pipe)        
    os.unlink(pipe)  

if __name__=="__main__":
    main()