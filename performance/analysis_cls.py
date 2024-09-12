import math
import re
import datetime

def timestr_to_obj(timestr):
    if timestr is None:
        return None
    return datetime.datetime.strptime(timestr.strip(),"%d/%m/%Y %H:%M:%S:%f").timestamp()
class Attack:
    def __init__(self,name,ts,host):
        self.name = name
        self.ts = timestr_to_obj(ts)
        self.host = host
        self.times = { "Symlink Attack": 5, "Dirty COW": 60, "Brute Force":60,"DoS": 60}
        self.end_ts = self.ts + self.times[self.name]
        self.host_map = { "VM1":["10.1.2.5","10.1.2.1"],"VM2":["10.1.2.10","10.1.2.1"],"LOCAL":["127.0.0.1","10.1.1.241"]}
        if ts is None or host is None: 
            self.id = None
        else:
            self.id = str(ts) + str(host)

    def get_class(self): 
        if (self.name in ["Brute Force","DoS"]): 
            return "Network"
        return "Host"
    
    def packet_in_attack(self,pack_ts): 
        return float(pack_ts) > self.ts and float(pack_ts) < self.end_ts

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

    ### Input ts as the original ts: group timestamp + analyser start time 
    def get_60s_ts(self,start,end,hosts):
        # print("FINDING ATTACKS NEAR",ts,hosts)
        relevant = []
        for atk in self.all:
            num = 0
            diff = start - atk.ts
            # print(atk.ts,diff)
            if diff > -1 and diff < 60 or atk.ts > start and atk.ts < end : 
                for i in hosts:
                    if i.startswith("10.42"):
                        num+=2
                    if i in atk.get_ips(): 
                        num+= 1
                if num == 3:
                    relevant.append(atk)
        return relevant

    # Pass raw packet timestamp and [srcip,dstip]
    def mark_packet(self,start,hosts):
        # print("FINDING ATTACKS NEAR",ts,hosts)
        for atk in self.all:
            num = 0 
            for i in hosts:
                if i.startswith("10.42"):
                    num += 2
                if i in atk.get_ips(): 
                    num+= 1
            if num == 3 and atk.packet_in_attack(start): 
                # print(str(atk))
                return True
        return False

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
        self.correct_pos = 0
        self.false_neg = 0
        self.true_neg = 0
        self.last_match = False

    def set_start(self,timestr):
        self.start_time = timestr_to_obj(timestr)

    def analyse_line(self,line,f,nested=False): 
        if re.match(r"[a-zA-Z]+:",line): 
            self.last_match = True
            return
            print("SYSCALL MAPPING:", line)
        elif re.match(r"(1:)|(\d+\.\d+):",line):
            self.total_count += 1
            # return
            # print("PACKET DETAILS:",line)
            one = line.split(": ")
            two = one[1].split("|")
            # print(one,"Two is ",two)
            rmse = one[0]
            name = two[0].replace("svc->",'').strip()
            sip = two[3].replace("sip->",'').strip()
            dip = two[4].replace("dip->",'').strip()
            ts = two[7].replace("ts->",'').strip()
            mark = self.attacks.mark_packet(ts,[sip,dip])
            if not self.last_match: 
                self.true_neg += 1
            self.last_match = mark
            if mark:
                self.pos += 1
            else: 
                self.neg += 1 
            self.last_details = [rmse,name,sip,dip]
        elif line.startswith("Request"):
            # return
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
            # print("|",datestr)
            # print(self.attacks.mark_packet)
            if self.attacks.mark_packet(pack_ts,[sip,dip]):
                self.correct_pos += 1
            # second = f.readline()
            # print("REQ_PACK COUNTS",second)
            # ben_c = second.split(" ")[0]
            # third = f.readline()
            self.last_details = [rmse,name,sip,dip]
            self.last_match = True
            # if (third.startswith("Terminated")):
            #     # print("REQUEST TERMINATED",line)
            #     self.add_request(Request(req_t,o_t,s_t,ben_c,datestr,pack_ts,sstr,self.last_details,True))
            # else:
            #     self.add_request(Request(req_t,o_t,s_t,ben_c,datestr,pack_ts,sstr,self.last_details))
            #     self.analyse_line(third,f)
        elif re.match(r"\d+ packets processed.",line):
            # self.total_count += 1000
            # print("GENERAL PACKET COUNTS", line)
            self.last_match = True
            pass
        else:
            self.last_match = True

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