from argparse import ArgumentParser
import matplotlib.pyplot as plt
import datetime
import math
import numpy as np
import os
import re
import time
import statistics

def timestr_to_obj(timestr):
    if timestr is None:
        return None
    return datetime.datetime.strptime(timestr.strip(),"%d/%m/%Y %H:%M:%S:%f").timestamp()
class Attack:
    def __init__(self,name,ts,host):
        self.name = name
        self.ts = timestr_to_obj(ts)
        self.host = host
        self.host_map = { "VM1":["10.1.2.5","10.1.2.1"],"VM2":["10.1.2.10","10.1.2.1"],"LOCAL":["127.0.0.1","10.1.1.241"]}

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
    def get_ips(self): 
        return self.host_map[self.host]
    
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
            if lowest is None: 
                # print("NEW LOWEST",diff,atk)
                lowest = diff
                stored = atk
            if diff < lowest: 
                lowest = diff 
                stored = atk
        if stored is None: 
            return None, Attack(None,None,None)
        return lowest, stored
    
    def get_host_atks(self,req):
        stored = None
        lowest = math.inf
        # print("Evaluating ", req)
        for atk in self.all:
            diff = req.ts - atk.ts
            num = 0
            if diff < lowest and diff > -5:
            # if lowest is None: 
            #     # print("NEW LOWEST",diff,atk)
            #     lowest = diff
            #     stored = atk
                for i in req.hosts:
                    if i.startswith("10.42"):
                        num+=2
                    if i in atk.get_ips(): 
                        num+= 1
                if num == 3:
                    # print("Ips matched",i,req.hosts)
                    lowest = diff 
                    stored = atk
            # if diff < lowest and atk.get_ip() in req.hosts: 
        if stored is None: 
            return None, Attack(None,None,None)
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
        self.hosts = pack[-2:]
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
        self.total_count = 0

    def set_start(self,timestr):
        self.start_time = timestr_to_obj(timestr)

    def analyse_line(self,line,f): 
        if re.match(r"[a-zA-Z]+:",line): 
            return
            print("SYSCALL MAPPING:", line)
        elif re.match(r"(1:)|(\d+\.\d+):",line):
            self.total_count += 1
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
            # self.total_count += 1
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
            self.total_count += 1000
            # print("GENERAL PACKET COUNTS", line)
            pass

    def analyse_comp_line(self,line):
        self.total_count += 1
        det = [x.strip() for x in line.strip().split(" ") if x.strip() != '']
        # print(line,det)
        if len(det) != 6:
            # print("Illegal line",line,det)
            return
        ts = det[0].replace("|",'').strip()
        rmse = det[-1]
        if float(rmse) < 0.4: 
            # print("Excluding",rmse)
            return
        else:
            sip = det[1]
            dip = det[2]
            last_details = [rmse,"compare",sip,dip]
            # print("added ",last_details, "from", det)
            self.add_request(Request(None,rmse,None,None,None,ts,None,last_details,True))

    def add_request(self,req): 
        # print("|",req)
        self.req_q.append(req)

def analyse_comparison(file_name):
    if not os.path.exists(file_name): 
        print("Invalid file for comparison.")
        return
    results = Analyser()
    with open(file_name,'r') as f:
        for line in f:
            results.analyse_comp_line(line)
    # print(results.req_q)
    # all_grps = get_groups_from_analyser(results)
    return results

def get_group_times(group_list,start_time): 
    atk_ranges = list()
    for grp in group_list:
        # print("Group",grp)
        start = grp[1] - start_time
        end = grp[2] -  start_time
        atk_ranges.append((int(start),int(end)))
    return atk_ranges

def get_groups_from_analyser(results,atks):
    groups = dict()
    count = 0
    fal_pos = 0
    true_pos = 0
    values = {"total":0,"within_90s":0,"correct_host":0}
    all_groups = list()
    host_list = []
    for r in results.req_q:
        # print("((",r,end=")),  ")
        # group_count += 1
        # count += 1
        near = atks.get_host_atks(r)
        # if near[0] is None: 
        #     host_no_attack += 1
        # elif near[0] < 95: 
        #     within_90s += 1
        #     print("Incremented",near[1],r)
        # else:
        #     print("Near nonnull",near,near[1])
        # Store groups = { hosts -> [ count,start_ts, end_ts ]}
        # print(near)
        # found = False
        host_str = ""
        # print("Adding",r.hosts,r.last_pack)
        for i,v in enumerate(sorted(r.hosts)):
            # print("Sorted",i,v)
            # print("adding",v)
            host_str += "-" + str(v)

        ##### GROUP COUNTING NOT WORKING PROPERLY #####


        if host_str not in host_list: 
            host_list.append(host_str)
        if host_str in groups:
            # print(host_str)
            # found = True
            groups[host_str][0] += 1
            # If there is a gap larger than 60 seconds between packets, end the current flow.
            if r.ts - groups[host_str][2] > 60:
                ### Terminate an old group
                if len(groups[host_str]) > 4:
                    groups[host_str][6] = to_date(groups[host_str][6])
                # groups[host_str].append(r.sysc_str)
                # if "10.1.2.5" in host_str: 
                # print(host_str,"Group ended:",groups[host_str])
                all_groups.append(groups[host_str].copy())
                values["total"] += 1

                # if groups[host_str][3] is not None and groups[host_str][3] < 90:
                #     print("Alert within 90s of attack:",r.o_trust,"x",r.s_trust,"-->",r.r_trust)
                #     values["within_90s"] += 1
                #     if host_map[groups[host_str][5]] in host_str: 
                #         print("Correct host matched.")
                #         values["correct_host"] += 1
                # print("NEW ATTACK GROUP",datetime.datetime.fromtimestamp(r.ts),r.hosts,r.o_trust,r.s_trust,near[0],near[1])
                # near = results.attacks.get_host_atks(r)
                if groups[host_str][3] is None:
                # if near[0] is None: 
                    fal_pos += groups[host_str][0]
                # elif near[0] < 90: 
                elif groups[host_str][3] < 60:
                # else:
                    true_pos += groups[host_str][0]
                    # print("Incremented",near[1],r)
                else:
                    fal_pos += groups[host_str][0]
                # count += 1
                groups[host_str] = [0,r.ts,r.ts,near[0],near[1].name,near[1].host,near[1].ts,r.hosts]                         
                # groups[host_str] = [0,r.ts,r.ts,near[0],near[1].name,near[1].host,near[1].ts,r.sysc_str]                        
            else: 
                groups[host_str][2] = r.ts 
        # if not found:
        else:
            ## Start a new group
            # near = results.attacks.get_host_atks(r)
            # if near[0] is None: 
            #     host_no_attack += 1
            # # elif near[0] < 300: 
            # else:
            #     within_90s += 1
            #     # print("Incremented",near[1],r)
            # count += 1 
            # print("NOT FOUND")
            groups[host_str] = [0,r.ts,r.ts,near[0],near[1].name,near[1].host,near[1].ts,r.hosts]      
    print("A_G:",all_groups)
    print("C_G",groups)
    count = results.total_count
    total_pos = fal_pos + true_pos
    print("PARSED ", count, "packets")
    print("LISTS",host_list)
    print("COUNTS", count, "FP",fal_pos,"prop FP",fal_pos/total_pos,"TP",true_pos,"prop",true_pos/total_pos)
    return all_groups

def to_date(times):
    if times is not None:
        return str(datetime.datetime.fromtimestamp(float(times)).time()) 

def parse_attack_file(file,start):
    atks = Attacks()
    if file is not None:
        print("Attack file given at",file)
        with open(file,"r") as atk_f: 
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
                    if atk_details.is_newer(start):
                        # print(atk_details)
                        atks.add_attack(atk_details)
                    # print("Parsed ts:",ts.strip(),"atk:",atk.strip(),"host",host)
                except:
                    pass
    else: 
        return
    atks.order()
    # for i in atks.all: 
    #     print("((",i,end=")),  ")
    # print("Found",len(atks.all),"attacks")
    return atks
    
def parse_log_file(fname):
    print(fname) 
    with open(fname,"r") as raw: 
        results = Analyser()
        line = raw.readline()
        print("|st",timestr_to_obj(line))
        results.set_start(line)        
        for line in raw: 
            # print(line)
            results.analyse_line(line,raw)
        return results

def get_average_atk_delay(atks):
    objs = []
    prev = None
    for i in atks.all: 
        cur = i.ts
        if prev is None: 
            prev = cur
            continue
        objs.append(cur-prev)
        prev = cur
    print(objs)
    print("Average delay",statistics.fmean(objs),statistics.median(objs))

def main(): 
    parser = ArgumentParser()
    parser.add_argument("file", help="Path of file to anlayse")
    parser.add_argument("-a","--attack-file",help="Path of file containing the attack logs")
    args = parser.parse_args()
    results = parse_log_file(args.file)
    atks = parse_attack_file(args.attack_file,results.start_time)
    get_average_atk_delay(atks)
    all_groups = get_groups_from_analyser(results,atks)
    print("ANALYSER COUNT",results.total_count)
    zt_rke2_group = get_group_times(all_groups,results.start_time)
    comp_analyser = analyse_comparison("../module/Kit_Agent/100k_minimal.log")
    print("ANALYSER COUNT",comp_analyser.total_count)
    comp_groups = get_groups_from_analyser(comp_analyser,atks)
    kit_group = get_group_times(comp_groups,results.start_time)
    # print("ZT_RKE2 GROUPS")
    # for i in all_groups: 
    #     print("(( ",i,end=" ))")
    # print("COMPARISON GROUPS")
    # for i in kit_group: 
    #     print("(( ",i,end=" ))")
    # from 22:15 to 23:05 
    # Create the line plot
    values = range(0, 3600)
    # target_ranges = [(5, 7), (34, 36)]
    ground_truths = dict()
    for atk in atks.all: 
        ground_truths[int(atk.ts - results.start_time)] = atk.get_class()
    # Create a list to store the corresponding values
    plot_values = []
    net_atks = []
    host_atks = []
    # print(results.start_time)
    # print(ground_truths)
    all_atks = []
    comp_vals = []
    # compare_ts = analyse_comparison("../module/Kit_Agent/100k_minimal.log")
    # for i,c_ts in enumerate(compare_ts): 
    #     compare_ts[i] = int(float(c_ts[0]) - results.start_time)
        # print(c_ts[1])
    # print("Compare",compare_ts)
    for value in values:
        if any(start <= value <= end for start, end in zt_rke2_group):
            plot_values.append(1)
        else:
            plot_values.append(None)
        if any(start <= value <= end for start, end in kit_group):
            comp_vals.append(1.25)
        else:
            comp_vals.append(None)

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
        # if value in compare_ts: 
        #     comp_vals.append(1.25)
        # else:
        #     comp_vals.append(None)
        # if 
    # print("Values",plot_values)
    # print(plot_2_values)
    plt.figure(figsize=(20,10))
    plt.plot(values, plot_values, drawstyle='steps-post',markersize=3,marker='o',label="Detected Attacks")
    plt.plot(values, host_atks, drawstyle='steps-post',color="orange",markersize=3,marker='o',label="Host Attacks")
    plt.plot(values, all_atks, drawstyle='steps-post',color="green",markersize=3,marker='o',label="All Attacks")
    plt.plot(values, net_atks, drawstyle='steps-post',color="red",markersize=3,marker='o',label="Network Attacks")
    plt.plot(values, comp_vals, drawstyle='steps-post',color="purple",markersize=3,marker='o',label="General model")
    plt.xlabel("Time since start (seconds)")

    plt.ylabel("Attack Category")
    plt.xticks(np.arange(0,3600,step=600))
    plt.yticks(np.arange(0,2,step=0.5))
    plt.legend()
    plt.title("Analysis of ZT-RKE2 model")
    # plt.savefig(f'out/31_8_{time.strftime("%Y%m%d-%H%M%S")}.png')
    # plt.show()


if __name__ == "__main__": 
    # analyse_comparison("../module/Kit_Agent/50k_minimal.log")
    main()
    