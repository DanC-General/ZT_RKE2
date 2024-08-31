from argparse import ArgumentParser
import datetime
import re
def timestr_to_obj(timestr):
    return datetime.datetime.strptime(timestr.strip(),"%d/%m/%Y %H:%M:%S:%f").timestamp()
class Attack:
    def __init__(self,name,ts,host):
        self.name = name
        self.ts = timestr_to_obj(ts)
        self.host = host
    def get_class(self): 
        if (self.name in ["Brute Force","DoS"]): 
            return "Network"
        return "Host"
    def is_newer(self,start_time): 
        return self.ts > start_time
    def __str__(self):
        ret = ""
        for k in vars(self): 
            ret += k+"->"+str(vars(self)[k])+" | "
        return ret
    
class Attacks: 
    def __init__(self): 
        self.all = list()
    def add_attack(self,atk): 
        self.all.append(atk)
    def order(self):
        self.all = sorted(self.all, key=lambda x: x.ts)
    def get_closest_atk(self,ts):
        stored = None
        lowest = None
        for atk in self.all:
            diff = ts - atk.ts 
            # print(ts,atk.ts,diff,atk)
            if diff < 0:
                continue
            if lowest is None: 
                lowest = diff
                stored = atk
            if diff < lowest: 
                lowest = diff 
                stored = atk
        return lowest, stored

        

class Request: 
    def __init__(self,r_t,o_t,s_t,benign,timestr,pack,term=False): 
        self.r_trust = r_t 
        self.s_trust = s_t 
        self.o_trust = o_t
        self.prev_benign = benign 
        # print("Converting",timestr, datetime.datetime.strptime(timestr,"%d/%m/%Y %H:%M:%S:%f"))
        self.ts = timestr_to_obj(timestr)
        self.terminated = term
        self.last_pack = pack
        self.hosts = set(pack[-2:])
    def __str__(self):
        ret = ""
        for k in vars(self): 
            ret += k+"->"+str(vars(self)[k])+" | "
        return ret
    
class Analyser:
    def __init__(self): 
        self.start_time = None
        self.req_q = list()
        self.attacks = Attacks()
        self.last_details = list()
    def set_start(self,timestr):
        self.start_time = timestr_to_obj(timestr)
    def analyse_line(self,line,f): 
        if re.match(r"[a-zA-Z]+:",line): 
            print("SYSCALL MAPPING:", line)
        elif re.match(r"(1:)|(\d+\.\d+):",line):
            print("PACKET DETAILS:",line)
            one = line.split(": ")
            two = one[1].split("|")
            print(one,"Two is ",two)
            rmse = one[0]
            name = two[0].replace("svc->",'').strip()
            sip = two[3].replace("sip->",'').strip()
            dip = two[4].replace("dip->",'').strip()
            self.last_details = [rmse,name,sip,dip]
        elif line.startswith("Request"):
            print("REQUEST DETAILS",line)
            details = line.split(" ")
            req_t = details[3]
            s_t = re.sub(r'[a-zA-Z]', '', details[6])
            o_t = re.sub(r'[a-zA-Z]', '', details[9])
            datestr = details[11] + " " + details[12]
            print("|",datestr)
            second = f.readline()
            print("REQ_PACK COUNTS",second)
            ben_c = second.split(" ")[0]
            third = f.readline()
            if (third.startswith("Terminated")):
                print("REQUEST TERMINATED",line)
                self.add_request(Request(req_t,o_t,s_t,ben_c,datestr,self.last_details,True))
            else: 
                self.add_request(Request(req_t,o_t,s_t,ben_c,datestr,self.last_details))
                self.analyse_line(third,f)
        elif re.match(r"\d+ packets processed.",line):
            print("GENERAL PACKET COUNTS", line)
        # elif line.startswith("Likelihood"): 
        #     print("LIKELIHOOD",line)
        #     weights = f.readline()
        #     print("WEIGHTS",weights)
        # else: 
        #     print(line)

    def add_request(self,req): 
        print("|",req)
        self.req_q.append(req)

def main(): 
    parser = ArgumentParser()
    parser.add_argument("file", help="Path of file to anlayse")
    parser.add_argument("-a","--attack-file",help="Path of file containing the attack logs")
    args = parser.parse_args()
    print(args.file) 
    with open(args.file,"r") as raw: 
        results = Analyser()
        line = raw.readline()
        print("|st",timestr_to_obj(line))
        results.set_start(line)
        if args.attack_file is not None:
            print("Attack file given at",args.attack_file )
            with open(args.attack_file,"r") as atk_f: 
                host="LOCAL"
                for line in atk_f:
                    # print("ATK LINE",line)
                    if "##" in line: 
                        host = line.replace("##","").strip()
                    try:
                        one = line.split('at')
                        ts = one[1]
                        two = one[0].split('malicious')
                        atk = two[1]
                        host = host 
                        atk_details = Attack(atk.strip(),ts.strip(),host.strip())
                        if atk_details.is_newer(results.start_time):
                            # print(atk_details)
                            results.attacks.add_attack(atk_details)
                        # print("Parsed ts:",ts.strip(),"atk:",atk.strip(),"host",host)
                    except:
                        pass
        results.attacks.order()
        for i in results.attacks.all: 
            print("((",i,end=")),  ")
        # return
        for line in raw: 
            # print(line)
            results.analyse_line(line,raw)
        groups = dict()
        # group_count = 0
        new_group = False
        last_ts = 0
        for r in results.req_q:
            # print("((",r,end=")),  ")
            # group_count += 1
            near = results.attacks.get_closest_atk(r.ts)
            # print(r)
            # if near[1] not in groups:
            #     groups[near[1]] = dict()
            #     groups[near[1]][r.hosts] = list()
            #     groups[near[1]][r.hosts][0] = 0
            #     groups[near[1]][r.hosts][1] = r.ts
            # else: 
            #     for k,v in groups[near[1]]:
            #         if set(k) == r.hosts: 
            #             groups[near[1]][r.hosts][0] += 1
            #             groups[near[1]][r.hosts][2] = r.ts
            if r.ts - last_ts > 3: 
                print("NEW ATTACK GROUP",datetime.datetime.fromtimestamp(r.ts),r.hosts,r.o_trust,r.s_trust)
            # print("DIFF",r.ts - last_ts)
            last_ts = r.ts
            # print("CLOSEST ATTACKS TO",r.ts,"==",near[0],near[1])


if __name__ == "__main__": 
    main()
    