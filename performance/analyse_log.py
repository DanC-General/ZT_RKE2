from argparse import ArgumentParser
import re
class Request: 
    def __init__(self,r_t,o_t,s_t,benign,timestr): 
        self.r_trust = r_t 
        self.s_trust = s_t 
        self.o_trust = o_t
        self.prev_benign = benign 
        self.ts = timestr
class Analyser:
    def __init__(self): 
        self.start_time = None
    def set_start(self,timestr):
        self.start_time = timestr
    def analyse_line(self,line,f): 
        if re.match(r"[a-zA-Z]+:",line): 
            print("SYSCALL MAPPING:", line)
        elif re.match(r"(1:)|(\d+\.\d+):",line):
            print("PACKET DETAILS:",line)
        elif line.startswith("Request"):
            print("REQUEST DETAILS",line)
            second = f.readline()
            print("REQ_PACK COUNTS",second)
            third = f.readline()
            if (third.startswith("Terminated")):
                print("REQUEST TERMINATED",line)
            else: 
                self.analyse_line(third,f)
        elif re.match(r"\d+ packets processed.",line):
            print("GENERAL PACKET COUNTS", line)
        elif line.startswith("Likelihood"): 
            print("LIKELIHOOD",line)
            weights = f.readline()
            print("WEIGHTS",weights)
        else: 
            print(line)
def main(): 
    parser = ArgumentParser()
    parser.add_argument("file", help="Path of file to anlayse")
    parser.add_argument("-a","--attack-file",help="Path of file containing the attack logs")
    args = parser.parse_args()
    print(args.file) 
    with open(args.file,"r") as raw: 
        results = Analyser()
        line = raw.readline()
        print(line)
        results.set_start(line)
        for line in raw: 
            # print(line)
            results.analyse_line(line,raw)


if __name__ == "__main__": 
    main()
    