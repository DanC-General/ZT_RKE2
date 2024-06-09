import os
import time

# class Subject:

# class Object: 
#     def __init__:

class Packet: 
    # Initialise the variables from the 
    #   packet list.
    def __init__(self,props): 
        self.svc = props[0]
        self.smac = props[1]
        self.dmac = props[2]
        self.sip = props[3]
        self.dip = props[4]
        self.ts = props[5]
        self.size = props[6]
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
            print(data)
            # Split the string into a list with the necessary 
            #   fields for class parsing.
            details = data.strip().split("|")
            pack = Packet(details)
            print(pack)  
            print(time.gmtime(int(pack.ts) / 1000000 )) 

def main(): 
    # Communication with scrape.c occurs
    #   through the "traffic_data" pipe. 
    pipe = "traffic_data"
    while not os.path.exists(pipe):
        pass  
    get_lines(pipe)        
    os.unlink(pipe)  

if __name__=="__main__":
    main()