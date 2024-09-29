import math
import re
import datetime
import numpy as np
import matplotlib.pyplot as plt
import time

def timestr_to_obj(timestr):
    if timestr is None:
        return None
    return datetime.datetime.strptime(timestr.strip(),"%d/%m/%Y %H:%M:%S:%f").timestamp()
class Attack:
    def __init__(self,name,ts,host):
        self.name = name
        self.start_ts = timestr_to_obj(ts)
        self.host = host
        self.times = { "Symlink Attack":1, "Dirty COW":3, "Brute Force":14,"DoS":12}
        self.end_ts = float(self.start_ts + self.times[self.name])
        self.host_map = { "VM1":["10.1.2.5","10.1.2.1","192.168.122.1","10.1.1.241"],"VM2":["10.1.2.10","10.1.2.1","192.168.122.1","10.1.1.241"],"LOCAL":["127.0.0.1","10.1.1.241","192.168.122.1","10.1.2.1"]}
        if ts is None or host is None: 
            self.id = None
        else:
            self.id = str(ts) + str(host)
        # print("Attacks", self.__str__())

    def get_class(self): 
        if (self.name in ["Brute Force","DoS"]): 
            return "Network"
        return "Host"
    
    def packet_in_attack(self,pack_ts): 
        # if float(pack_ts) > self.start_ts and float(pack_ts) < self.end_ts:
        #     print(pack_ts, "between", self.start_ts,self.end_ts)
        # else: 
        #     print(pack_ts, "not between", self.start_ts,self.end_ts)
        return float(pack_ts) > self.start_ts and float(pack_ts) < self.end_ts

    def is_newer(self,start_time): 
        return self.start_ts > start_time
    def __str__(self):
        ret = ""
        for k in vars(self): 
            ret += k+"->"+str(vars(self)[k])+" | "
        return ret
    def get_ips(self): 
        return self.host_map[self.host]
    def start_time(self): 
        return self.start_ts
    
class Attacks: 
    def __init__(self): 
        self.all = list()

    def add_attack(self,atk): 
        self.all.append(atk)
    def order(self):
        self.all = sorted(self.all, key=lambda x: x.start_time())
        
    # def get_closest_atk(self,ts):
    #     # print("FINDING CLOSEST ATTACK TO",to_date(ts))
    #     stored = None
    #     lowest = None
    #     for atk in self.all:
    #         diff = abs(ts - atk.start_time())
    #         if lowest is None: 
    #             # print("NEW LOWEST",diff,atk)
    #             lowest = diff
    #             stored = atk
    #         if diff < lowest: 
    #             lowest = diff 
    #             stored = atk
    #     if stored is None: 
    #         return None, Attack(None,None,None)
    #     return lowest, stored
    
    # def get_host_atks(self,req):
    #     stored = None
    #     lowest = math.inf
    #     # print("Evaluating ", req)
    #     for atk in self.all:
    #         diff = req.ts - atk.start_time()
    #         num = 0
    #         if diff < lowest and diff > -5:
    #         # if lowest is None: 
    #         #     # print("NEW LOWEST",diff,atk)
    #         #     lowest = diff
    #         #     stored = atk
    #             for i in req.hosts:
    #                 if i.startswith("10.42"):
    #                     num+=2
    #                 if i in atk.get_ips(): 
    #                     num+= 1
    #             if num == 3:
    #                 # print("Ips matched",i,req.hosts)
    #                 lowest = diff 
    #                 stored = atk
    #         # if diff < lowest and atk.get_ip() in req.hosts: 
    #     if stored is None: 
    #         return None, Attack(None,None,None)
    #     return lowest, stored

    # ### Input ts as the original ts: group timestamp + analyser start time 
    # def get_60s_ts(self,start,end,hosts):
    #     # print("FINDING ATTACKS NEAR",ts,hosts)
    #     relevant = []
    #     for atk in self.all:
    #         num = 0
    #         diff = start - atk.start_time()
    #         # print(atk.start_time(),diff)
    #         if diff > -1 and diff < 60 or atk.start_time() > start and atk.start_time() < end : 
    #             for i in hosts:
    #                 if i.startswith("10.42"):
    #                     num+=2
    #                 if i in atk.get_ips(): 
    #                     num+= 1
    #             if num == 3:
    #                 relevant.append(atk)
    #     return relevant

    # Pass raw packet timestamp and [srcip,dstip]
    # Returns True for malicious packets and False for benign
    def mark_packet(self,start,hosts):
        # print("FINDING ATTACKS NEAR",ts,hosts)
        type = None 
        for atk in self.all:
            num = 0 
            for i in hosts:
                if i.startswith("10.42"):
                    num += 2
                if i in atk.get_ips(): 
                    num+= 1
            if num == 3 and atk.packet_in_attack(start): 
            # if atk.packet_in_attack(start):
                # print(str(atk))
                return True, atk.get_class()
        return False, None

    def justify_exclusions(self,start,hosts):
        reasons = []
        for atk in self.all:
            num = 0 
            # for i in hosts:
            #     if i.startswith("10.42"):
            #         num += 2
            #     if i in atk.get_ips(): 
            #         num+= 1
            # if num != 3: 
            #     continue
            start = float(start)
            if atk.packet_in_attack(start):
                reasons.append("TIME"+str(atk.start_time())+"::" + str(atk.get_ips()[0])+":"+str(atk.name))
                # reasons.append("HOSTS-"+str(atk.get_ips()[0]))
            # if not atk.packet_in_attack(start):
            #     reasons.append("TIME"+str(atk.start_time()))
        return reasons

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
        self.neg = 0
        self.pos = 0
        self.true_pos = 0
        self.false_pos = 0
        self.false_neg = 0
        self.true_neg = 0
        self.ground_pos_times = []
        self.net_gt = []
        self.host_gt = []
        self.fptimes = []
        self.tptimes = []
        self.fntimes = []
        self.avg_times = []
        # Net [TP,FN] : Host [TP,FN]
        self.cls_detection = [ [0,0],[0,0]]
        self.last_match = False

    def set_start(self,timestr):
        self.start_time = timestr_to_obj(timestr)

    def analyse_line(self,line,f,nested=False): 
        if re.match(r"[a-zA-Z]+:",line): 
            return
            print("SYSCALL MAPPING:", line)
        elif re.match(r"(1:)|(\d+\.\d+):",line):
            self.total_count += 1
            one = line.split(": ")
            two = one[1].split("|")
            rmse = one[0]
            name = two[0].replace("svc->",'').strip()
            sip = two[3].replace("sip->",'').strip()
            dip = two[4].replace("dip->",'').strip()
            ts = two[7].replace("ts->",'').strip()
            is_malicious_packet, atk_type = self.attacks.mark_packet(ts,[sip,dip])
            if is_malicious_packet:
                self.pos += 1
                self.ground_pos_times.append(ts)
                if atk_type == "Network": 
                    self.net_gt.append(ts)
                elif atk_type == "Host": 
                    self.host_gt.append(ts)
            else: 
                self.neg += 1 
            pos = f.tell()
            next_line = f.readline()
            sys_alert = False
            if next_line.startswith("Request"):
                # Alert was raised
                sys_alert = True
            # For a false negative, there would have been an attack (is_malicious_packet True) 
            #   and no alert would have been raised (mark False)
            if not sys_alert and is_malicious_packet: 
                self.false_neg += 1
                self.fntimes.append(ts)
                self.last_match = "FN"
                if atk_type == "Host": 
                    self.cls_detection[1][1] += 1
                elif atk_type == "Network": 
                    self.cls_detection[0][1] += 1
            # For a true negative, there should have been no attack (is_malicious_packet False)
            #   and no attack should have been raised (mark False)
            elif not sys_alert and not is_malicious_packet: 
                self.true_neg += 1
                self.last_match = "TN"
            # For a true positive, the system would detect an alert and the packet would be 
            #   malicious.
            elif sys_alert and is_malicious_packet: 
                self.true_pos += 1
                self.tptimes.append(ts)
                self.last_match = "TP"
                if atk_type == "Host": 
                    self.cls_detection[1][0] += 1
                elif atk_type == "Network": 
                    self.cls_detection[0][0] += 1
            # For a false positive, the system would detect an alert but the packet would be 
            #   benign.
            elif sys_alert and not is_malicious_packet:
                # print("False positive",[sip,dip,datetime.datetime.fromtimestamp(float(ts))])
                self.fptimes.append(ts)
                self.false_pos += 1
                self.last_match = "FP"

            f.seek(pos)

            self.last_details = [rmse,name,sip,dip]
        elif line.startswith("Request"):
            no_sysc = re.sub(r"[a-zA-Z]+:: {.*}",' ',line)
            sstr = re.search(r"[a-zA-Z]+:: {.*}",line).group()
            # print("NS",no_sysc)
            if not self.last_match == "FP":
                return
            one = no_sysc.split("svc->")
            # for i,e in enumerate(one): 
            #     print("ONE",i,e)
            req_dets = one[0].strip().split(' ')
            pack_dets = one[1]

            ## Parse packet
            p_d = pack_dets
            els = p_d.split("|")
            name = els[0].replace("svc->",'').strip()
            sip = els[3].replace("sip->",'').strip()
            dip = els[4].replace("dip->",'').strip()
            pack_ts = els[7].replace("ts->",'').strip()
            ## Parse request

            req_t = req_dets[3]
            s_t = re.sub(r'[a-zA-Z]', '', req_dets[6])
            o_t = re.sub(r'[a-zA-Z]', '', req_dets[9])
            rmse = req_dets[-1].replace(':','')
            # sip = re.sub(r'[a-zA-Z:]', '', req_dets[])
            datestr = req_dets[11] + " " + req_dets[12]
            # print("|",datestr
            second = f.readline()
            # print("REQ_PACK COUNTS",second)
            # print(pack_ts,sip,dip,":",s_t,rmse,req_t,self.attacks.justify_exclusions(pack_ts,[sip,dip]))
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
            # self.total_count += 1000
            # print("GENERAL PACKET COUNTS", line)
            pass
        elif line.startswith("Time"):
            # print(line,line.split(" "))
            det = line.split(" ") 
            req_ts = None
            if len(det) == 2: 
                proc_time = float(det[1]) 
            else:
                proc_time = float(det[2]) 
                req_ts = float(det[3]) - self.start_time
            self.avg_times.append((proc_time,req_ts))

    def analyse_comp_line(self,line,rmse_cutoff=0.1):
        self.total_count += 1
        det = [x.strip() for x in line.strip().split(" ") if x.strip() != '']
        # print(line,det)
        if len(det) == 8: 
            del det[2]
            del det[3]
        if len(det) != 6 :
            # print("Illegal line",line,det)
            return
        ts = det[0].replace("|",'').strip()
        rmse = det[-1]
        # if float(rmse) < 0.4: 
        #     # print("Excluding",rmse)
        #     return
        # else:
        sip = det[1]
        dip = det[2]
        # print(rmse,sip,dip)
        last_details = [rmse,"compare",sip,dip]
        mark = False
        if float(rmse) > rmse_cutoff:
            mark = True
        actual_mark, atk_type = self.attacks.mark_packet(ts,[sip,dip])
        if actual_mark:
            self.pos += 1
            self.ground_pos_times.append(ts)
            if atk_type == "Network": 
                self.net_gt.append(ts)
            elif atk_type == "Host": 
                self.host_gt.append(ts)

            if mark: 
                self.true_pos += 1
                self.tptimes.append(ts)
                if atk_type == "Host": 
                    self.cls_detection[1][0] += 1
                elif atk_type == "Network": 
                    self.cls_detection[0][0] += 1
            else: 
                self.false_neg += 1 
                self.fntimes.append(ts)
                if atk_type == "Host": 
                    self.cls_detection[1][1] += 1
                elif atk_type == "Network": 
                    self.cls_detection[0][1] += 1
       
        else:
            self.neg += 1
            if not mark: 
                self.true_neg += 1
            else: 
                self.false_pos += 1 
                self.fptimes.append(ts) 
            # print("added ",last_details, "from", det)
            # self.add_request(Request(None,rmse,None,None,None,ts,None,last_details,True))

    def add_request(self,req): 
        # print("|",req)
        self.req_q.append(req)

    def get_stats(self): 
        total_pos = self.pos 
        total_neg = self.neg
        # print("Total positives:",total_pos, "Total negatives:",total_neg)
        t_p = self.true_pos
        f_p = self.false_pos
        t_n = self.true_neg
        f_n = self.false_neg
        if t_p == 0:
            t_p = 1
        # print("True positives:",t_p,"False postives:", f_p ,"True negatives:",t_n,"False negatives:",f_n)
        acc = (t_p + t_n) / (t_p + t_n + f_p + f_n)
        prec = t_p / (t_p + f_p)
        rec = t_p / (t_p + f_n)
        f1 = 2 * (prec * rec) / (prec + rec)
        # print("Accuracy:", acc, "Precision:",prec,"Recall:",rec,"F1 Score:",f1)
        # print(self.cls_detection)
        if self.cls_detection[0][0] == 0 or self.cls_detection[1][0] == 0:
            self.cls_detection = [[1,1],[1,1]]
        # print("Class detection",self.cls_detection, 1 - (self.cls_detection[0][1]/(self.cls_detection[0][0]+self.cls_detection[0][1])), 1 - (self.cls_detection[1][1]/(self.cls_detection[1][1]+self.cls_detection[1][0])))
        return t_p,f_p,t_n,f_n,acc,prec,rec,f1, 1 - (self.cls_detection[0][1]/(self.cls_detection[0][0]+self.cls_detection[0][1])), 1 - (self.cls_detection[1][1]/(self.cls_detection[1][1]+self.cls_detection[1][0]))
        # return

    def get_visuals(self,name,is_ztrke2): 
        ground_truth_table = [int(float(x) - self.start_time) for x in self.ground_pos_times]
        host_gt_table = [int(float(x) - self.start_time) for x in self.host_gt]
        net_gt_table = [int(float(x) - self.start_time) for x in self.net_gt]
        fn_table = [int(float(x) - self.start_time) for x in self.fntimes]
        tp_table = [int(float(x) - self.start_time) for x in self.tptimes]

        gt_vals = []
        fn_vals = []
        tp_vals = []
        host_vals = []
        net_vals = []
        values = range(0, 3600)
        if is_ztrke2: 
            name_str = "ZT_RKE2"
        else:  
            name_str = "Kitsune"
        for value in values: 
            # if value in ground_truth_table:
            gt_vals.append(1 if value in ground_truth_table else None)
            fn_vals.append(0.4 if value in fn_table else None)
            tp_vals.append(0.35 if value in tp_table else None)
            host_vals.append(0.2 if value in host_gt_table else None)
            net_vals.append(0.2 if value in net_gt_table else None)
            # else:
            #     gt_vals.append(None)
            # if value in host_vals: 

            # if value in fn_table:
            #     fn_vals.append(2)
            # else:
            #     fn_vals.append(None)
            # if value in tp_table:
            #     tp_vals.append(1.5)
            # else:
            #     tp_vals.append(None)
        plt.figure(figsize=(20,10))
        # print(gt_vals,"___",tp_vals,"___",fn_vals)
        # plt.plot(values, gt_vals, drawstyle='steps-post',markersize=3,marker='o',label="All Attacks")
        plt.plot(values, tp_vals, drawstyle='steps-post',color="green",markersize=7,marker='o',label="True Positives")
        plt.plot(values, fn_vals, drawstyle='steps-post',color="red",markersize=7,marker='o',label="False Negatives")
        plt.plot(values, host_vals, drawstyle='steps-post',color="orange",markersize=7,marker='o',label="Host Attacks")
        plt.plot(values, net_vals, drawstyle='steps-post',color="purple",markersize=7,marker='o',label="Network Attacks")
        plt.xlabel("Time since start (seconds)",fontsize=18)

        plt.ylabel("Attack Category",fontsize=18)
        plt.xticks(np.arange(0,3600,step=600),fontsize=18)
        plt.yticks(np.arange(0,0.6,step=0.1),fontsize=18,color="white")
        plt.tick_params(
            axis='y',
            which='both',
            color='white'
        )
        plt.legend(fontsize=18,loc="upper left")
        plt.title(f"Analysis of {name_str} Recall",fontsize=22)
        plot_time = time.strftime("%Y%m%d-%H%M%S")
        print(name[:name.rfind("/")+1])
        out_dir = name[:name.rfind("/")+1]
        plt.savefig(f'{out_dir}{name_str}_Recall.png')
        # plt.show()
        
    def get_res_performance(self): 
        # print(self.avg_times)
        print([[x.alert_ts - self.start_time,x.r_trust] for x in list(self.req_q)])
        alert_details = [[x.alert_ts - self.start_time,float(x.r_trust)/float(10)] for x in list(self.req_q)]
        req_times = [x[0] for x in alert_details]
        # req_val = [0.8] * len(req_times)
        req_val = [x[1] for x in alert_details] 
        x, y = zip(*self.avg_times)
        # print(x, y)
        # Create the scatter plot
        plt.figure(figsize=(20,8))
        plt.scatter(y, x)
        plt.scatter(req_times, req_val, label='Detected requests')
        plt.legend()
        plt.xlabel('Time since start (seconds)',fontsize=18)
        plt.ylabel('Packet processing time',fontsize=18)
        plt.ylim(0,1)
        plt.title('Comparison of ZT_RKE2 processing times.',fontsize=18)
        # Show the plot
        # plt.show()
        plt.savefig("resource_util/ztrke2_packet_processing_adj.png")