from argparse import ArgumentParser
import matplotlib.pyplot as plt
import datetime
import numpy as np
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
        # print("FINDING CLOSEST ATTACK TO",to_date(ts))
        stored = None
        lowest = None
        for atk in self.all:
            diff = abs(ts - atk.ts)
            # print("DIFF for atk",ts,atk.ts,diff,atk)
            # if diff < 0:
            #     continue
            if lowest is None: 
                # print("NEW LOWEST",diff,atk)
                lowest = diff
                stored = atk
            if diff < lowest: 
                lowest = diff 
                stored = atk
        return lowest, stored

        

class Request: 
    def __init__(self,r_t,o_t,s_t,benign,alert_ts,timestr,sstr,pack,term=False): 
        self.r_trust = r_t 
        self.s_trust = s_t 
        self.o_trust = o_t
        self.alert_ts = timestr_to_obj(alert_ts)
        self.prev_benign = benign 
        # print("Converting",timestr, datetime.datetime.strptime(timestr,"%d/%m/%Y %H:%M:%S:%f"))
        self.ts = float(timestr)
        self.terminated = term
        self.last_pack = pack
        self.hosts = set(pack[-2:])
        self.sysc_str = sstr
    def __str__(self):
        ret = ""
        for k in vars(self): 
            ret += k+"->"+str(vars(self)[k])+" | "
        return ret
    def make_host_str(self): 
        host_str = ""
        for i,v in enumerate(sorted(self.hosts)):
            # print("Sorted",i,v)
            host_str += "-" + str(v)
        return host_str
    
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
            return
            print("SYSCALL MAPPING:", line)
        elif re.match(r"(1:)|(\d+\.\d+):",line):
            return
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
            # print("REQUEST DETAILS",line)
            # details = line.split(" ")
            ## Parse request into request, syscalls and packet
            no_sysc = re.sub(r"[a-zA-Z]+:: {.*}",' ',line)
            sstr = re.search(r"[a-zA-Z]+:: {.*}",line).group()
            # print("NS",no_sysc)
            one = no_sysc.split("svc->")
            # for i,e in enumerate(one): 
            #     print("ONE",i,e)
            req_dets = one[0].strip().split(' ')
            pack_dets = one[1]

            ## Parse packet
            p_d = pack_dets
            els = p_d.split("|")
            # print("p_d",p_d,"els is ",els)
            # for i,e in enumerate(els): 
            #     print("ELS",i,e)
            name = els[0].replace("svc->",'').strip()
            sip = els[3].replace("sip->",'').strip()
            dip = els[4].replace("dip->",'').strip()
            pack_ts = els[7].replace("ts->",'').strip()
            ## Parse request
            # print("REQ_DETS",req_dets,"PACK_DETS",pack_dets)
            # for i,e in enumerate(req_dets): 
            #     print("REQS",i,e)
            req_t = req_dets[3]
            s_t = re.sub(r'[a-zA-Z]', '', req_dets[6])
            o_t = re.sub(r'[a-zA-Z]', '', req_dets[9])
            rmse = req_dets[-1].replace(':','')
            # sip = re.sub(r'[a-zA-Z:]', '', req_dets[])
            datestr = req_dets[11] + " " + req_dets[12]
            # print("|",datestr)
            second = f.readline()
            # print("REQ_PACK COUNTS",second)
            ben_c = second.split(" ")[0]
            third = f.readline()
            self.last_details = [rmse,name,sip,dip]
            if (third.startswith("Terminated")):
                # print("REQUEST TERMINATED",line)
                self.add_request(Request(req_t,o_t,s_t,ben_c,datestr,pack_ts,sstr,self.last_details,True))
            else:
                self.add_request(Request(req_t,o_t,s_t,ben_c,datestr,pack_ts,sstr,self.last_details))
                self.analyse_line(third,f)
        elif re.match(r"\d+ packets processed.",line):
            # print("GENERAL PACKET COUNTS", line)
            pass
        # elif line.startswith("Likelihood"): 
        #     print("LIKELIHOOD",line)
        #     weights = f.readline()
        #     print("WEIGHTS",weights)
        # else: 
        #     print(line)

    def add_request(self,req): 
        # print("|",req)
        self.req_q.append(req)

def to_date(times):
    if times is not None:
        # print(type(time))
        
        return str(datetime.datetime.fromtimestamp(float(times)).time())
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
                        if "ORDERED" in line: 
                            break
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

        print("Found",len(results.attacks.all),"attacks")
        # return
        for line in raw: 
            # print(line)
            results.analyse_line(line,raw)
        groups = dict()
        # group_count = 0
        new_group = False
        last_ts = 0
        count = 0
        host_map = { "VM1":"10.1.2.5","VM2":"10.1.2.10","LOCAL":"127.0.0.1"}
        values = {"total":0,"within_90s":0,"correct_host":0}
        all_groups = list()
        for r in results.req_q:
            # print("((",r,end=")),  ")
            # group_count += 1
            count += 1
            near = results.attacks.get_closest_atk(r.ts)
            # if count > 3:
            #     break
            # Store groups = { hosts -> [ count,start_ts, end_ts ]}
            found = False
            host_str = ""
            for i,v in enumerate(sorted(r.hosts)):
                # print("Sorted",i,v)
                host_str += "-" + str(v)
            if host_str in groups:
                found = True
                groups[host_str][0] += 1
                if r.ts - groups[host_str][2] > 60:
                    # print(groups[host_str])
                    # groups[host_str][1] = to_date(groups[host_str][1])
                    # groups[host_str][2] = to_date(groups[host_str][2])
                    if len(groups[host_str]) > 4:
                        # try:
                        #     print(type(groups[host_str][-1]),groups[host_str][-1])
                        #     groups[host_str][-1] = groups[host_str][-1].time()
                        # # .date()
                        # except: 
                        #     print("In loop" ,groups[host_str][-1])
                        groups[host_str][6] = to_date(groups[host_str][6])
                    # groups[host_str].append(r.sysc_str)
                    # if "10.1.2.5" in host_str: 
                    print(host_str,"Group ended:",groups[host_str])
                    all_groups.append(groups[host_str].copy())
                    values["total"] += 1
                    if len(groups[host_str]) > 3 and groups[host_str][3] < 90:
                        print("Alert within 90s of attack:",r.o_trust,"x",r.s_trust,"-->",r.r_trust)
                        values["within_90s"] += 1
                        if host_map[groups[host_str][5]] in host_str: 
                            print("Correct host matched.")
                            values["correct_host"] += 1
                    # print("NEW ATTACK GROUP",datetime.datetime.fromtimestamp(r.ts),r.hosts,r.o_trust,r.s_trust,near[0],near[1])
                    near = results.attacks.get_closest_atk(r.ts)
                    groups[host_str] = [0,r.ts,r.ts,near[0],near[1].name,near[1].host,near[1].ts]                         
                    # groups[host_str] = [0,r.ts,r.ts,near[0],near[1].name,near[1].host,near[1].ts,r.sysc_str]                        
                else: 
                    groups[host_str][2] = r.ts 
            if not found:
                near = results.attacks.get_closest_atk(r.ts)
                groups[host_str] = [0,r.ts,r.ts,near[0],near[1].name,near[1].host,near[1].ts]                         
                # groups[host_str] = [0,r.ts,r.ts,near[0],near[1].name,near[1].host,near[1].ts,r.sysc_str]                         
            # if r.ts - last_ts > 3: 
            #     print("NEW ATTACK GROUP",datetime.datetime.fromtimestamp(r.ts),r.hosts,r.o_trust,r.s_trust,near[0],near[1])
            # print("DIFF",r.ts - last_ts)
            # print("CLOSEST ATTACKS TO",r.ts,"==",near[0],near[1])
        print(values)
        print("ALL GROUPS:",all_groups)
        atk_ranges = list()
        for grp in all_groups:
            # print(grp)
            start = grp[1] - results.start_time
            end = grp[2] -  results.start_time
            atk_ranges.append((int(start),int(end)))
            # print(start,end)

        # from 22:15 to 23:05 
        # Create the line plot
        values = range(0, 3600)
        # target_ranges = [(5, 7), (34, 36)]
        ground_truths = dict()
        for atk in results.attacks.all: 
            # print(int(atk.ts - results.start_time))
            ground_truths[int(atk.ts - results.start_time)] = atk.get_class()
        # Create a list to store the corresponding values
        plot_values = []
        net_atks = []
        host_atks = []
        # print(results.start_time)
        # print(ground_truths)
        all_atks = []
        for value in values:
            if any(start <= value <= end for start, end in atk_ranges):
                plot_values.append(1)
            else:
                plot_values.append(None)
            if value in ground_truths:
                all_atks.append(0.25)
                if ground_truths[value] == "Network": 
                    net_atks.append(0.75)
                    host_atks.append(None)
                else: 
                    host_atks.append(0.5)
                    net_atks.append(None)
            else:
                net_atks.append(None)
                all_atks.append(None)
                host_atks.append(None)
        # print(plot_values)
        # print(plot_2_values)
        plt.figure(figsize=(20,10))
        plt.plot(values, plot_values, drawstyle='steps-post',markersize=3,marker='o',label="Detected Attacks")
        plt.plot(values, host_atks, drawstyle='steps-post',color="orange",markersize=3,marker='o',label="Host Attacks")
        plt.plot(values, all_atks, drawstyle='steps-post',color="green",markersize=3,marker='o',label="All Attacks")
        plt.plot(values, net_atks, drawstyle='steps-post',color="red",markersize=3,marker='o',label="Network Attacks")
        plt.xlabel("Time since start (seconds)")
        plt.ylabel("Attack Category")
        plt.xticks(np.arange(0,3600,step=600))
        plt.yticks(np.arange(0,2,step=0.5))
        plt.legend()
        plt.title("Analysis of ZT-RKE2 model")
        plt.savefig("31_8.png")
        plt.show()

if __name__ == "__main__": 
    main()
    