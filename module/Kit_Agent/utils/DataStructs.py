from collections import deque
from netaddr import IPNetwork, IPAddress
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
        self.ts = float(props[7]) / float(1000000)
        self.size = int(props[8])
        self.flags = int(props[9])

    def __str__(self):
        ret = ""
        for k in vars(self): 
            ret += k+"->"+str(vars(self)[k])+" | "
        return ret
    
    def get_tcp_flags(self):
        """
        This function takes a byte value representing the TCP flags field and returns a list of the set flags.

        Args:
            flags_byte: A byte value representing the TCP flags field.

        Returns:
            A list of strings representing the set TCP flags (e.g., ["SYN", "ACK"]).
        """

        # Flag names and their corresponding bit positions
        flag_names = {
            1: "URG",
            2: "SYN",
            4: "ACK",
            8: "PSH",
            16: "RST",
            32: "FIN",
        }
        results = [1,2,4,8,16,32]
        set_flags = []
        for i,val in enumerate(results):
            # Check if the bit is set (value 1) using bitwise AND
            if self.flags & val:
                set_flags.append(flag_names[val])
                results[i] = 1
            else:
                results[i] = 0
        return set_flags,results

    def return_ml_data(self,stat_dict):
        _, flags = self.get_tcp_flags()
        cur_stats = stat_dict[self.svc]
        return [self.ts,self.size, self.svc,self.sip,self.dip,self.sport,
                self.dport] + flags + [cur_stats.mean_size, cur_stats.time_diff()[0]]
    
    def external_port(self,pod_cidr): 
        """ 
        Returns the port used in the external communication.
        If the source IP is the pods', return destination port 
            and vice versa. 
        """
        if IPAddress(self.sip) in IPNetwork(pod_cidr):
            # print("Source is pod")
            return self.dip, self.dport
        elif IPAddress(self.dip) in IPNetwork(pod_cidr):
            # print("Dest is pod")
            return self.sip, self.sport
        else: 
            print("Neither is pod")
            return -1
        
class PrioQ:
    def __init__(self):
        self.store = list()
    # Take [ts, host] items    
    def add(self,item): 
        # print("Adding item",item)
        ind = self.contains(item[1])
        # print("Item at index",ind)
        # Update existing entries with new timestamps
        if ind is not None:
            if item[0] > self.store[ind][0]:
                self.store[ind] = item
        # If the entry doesn't exists and the list isn't full, add it
        elif not self.full():
            self.store.append(item)
        # If the entry doesn't exist but the list is full,
        #       remove the oldest entry and add the new one
        #       if it is newer (assumes oldest entry is 
        #       at the start of the sorted list)
        elif item[0] > self.store[0][0]:
            self.store[0] = item
        self.store.sort()
        # print("Added", self.store)
    ## TODO Need to review this 
    def more_recent(self,ts):
        print("CHECKING",ts)
        rec = list()
        ts = float(ts)
        for i in self.store: 
            delta = ts - i[0]
            # print(delta)
            print("    ||",ts, "<->",i, " =",delta)
            if delta <= 5 and delta >= 0: 
                print("     added")
                # print("    -->",i[1], " has relevant delta",delta,": added!")
                rec.append(i[1])
        print(rec)
        rec.reverse()
        print(rec,"\n")
        return rec
    def empty(self): 
        return len(self.store) == 0
    def full(self):
        return len(self.store) == 3
    def contains(self, str):
        ind = 0
        for i in self.store: 
            if i[1] == str:
                return ind
            ind += 1
        return None 
    def __str__(self) -> str:
        return str(self.store)

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
    
# Stores statistics for the last 100 packets
class StatTracker: 

    def __init__(self): 
        self.packets = deque(maxlen=100)
        self.mean_size = 0

    def enqueue(self,pack: Packet): 
        sz = int(pack.size)
        # self.packets.append([datetime.datetime.fromtimestamp(int(pack.ts)),int(pack.size)])
        self.packets.append([float(pack.ts), sz])
        self._update_stats(pack)
        
    def _update_stats(self,pack:Packet): 
        sz = int(pack.size)
        if self.mean_size == 0: 
            self.mean_size = sz
        else: 
            prev_mean = self.mean_size
            self.mean_size = ((prev_mean * (len(self.packets) - 1)) + sz )/ (len(self.packets))

    def time_diff(self):
        change = self.packets[-1][0] - self.packets[0][0]
        return change , len(self.packets)
    
# class Service: 
#     def __init__(self,maxAE,FMgrace,ADgrace,name,port): 
#         self.subj_sysc_map = dict()
#         self.prev_subj = PrioQ()
#         self.terminated = dict()
#         self.ml = Kitsune(None,None,maxAE,FMgrace,ADgrace)
#         self.stats = StatTracker()
#         self.name = name
#         self.port = port

#     def total_abnormal(self): 
#         total = 0
#         for subject in self.subj_sysc_map: 
#             if "total" in self.subj_sysc_map[subject]:
#                 total += self.subj_sysc_map[subject]["total"]
#         return total
    
#     def handle_alert(self,syscall,alert_ts,log): 
#         # print("Recieved an alert!!")
#         # print(item)
#         log.write(syscall + str(alert_ts) + "\n")
#         recency = 5
#         # Change to use alert ts
#         for subject in self.prev_subj.more_recent(alert_ts): 
#             print("Adding to malicious", subject)
#             # if subject not in subj_sysc_map: 
#             #     subj_sysc_map[subject] = dict()
#             # else: 
#             #     # if "total" not in subj_sysc_map[subject]: 
#             #     #     subj_sysc_map[subject]["total"] = 1 * recency
#             self.subj_sysc_map[subject]["total"] += 1 * recency
#             if syscall not in self.subj_sysc_map[subject]:
#                 self.subj_sysc_map[subject][syscall] = 1 * recency
#             else:
#                 self.subj_sysc_map[subject][syscall] += 1 * recency
#             # Update so next subject is less recent
#             recency -= 2
#         log.write(self.name + ":: " + str(self.subj_sysc_map) + "\n")

#     def add_recent(self,subject,time): 
#         cur_sysc_map = self.subj_sysc_map
#         if subject not in cur_sysc_map: 
#             cur_sysc_map[subject] = dict()
#             print("Map did not contain ", subject)
#         if "total" not in cur_sysc_map[subject]: 
#             cur_sysc_map[subject]["total"] = 0
#             print(subject, "did not contain total")

#         if not self.prev_subj.contains(subject):
#             print("APPENDING ", subject, "to ",self.name, "\n")
#             self.prev_subj.add((time,subject))
#             print(self.prev_subj)
        
#     def subject_trust(self,subject,cur_call,log):
#         subj_trust = -1
#         total_ab_sys = self.total_abnormal()
#         smap = self.subj_sysc_map
#         if smap[subject]["total"] > 0 and total_ab_sys > 0 :
#             print("Set subject trust to ", smap[subject]["total"],"/",total_ab_sys," = ",int(smap[subject]["total"])/int(total_ab_sys))
#             subj_trust = int(smap[subject]["total"])/int(total_ab_sys)
#             log.write("Subject trust for " + subject + ": " + str(subj_trust) + "\n")
#             if cur_call in smap: 
#                 if smap[subject][cur_call] != 1: 
#                     print("Repeat syscall ",cur_call, ", skipping.")
#                     subj_trust = -1
#         smap[subject]["trust"] = subj_trust
#         log.write(self.name + ":: " + str(self.subj_sysc_map) + "\n")
#         return subj_trust
    
#     def terminate(self,orig_sip,orig_sport,log):
#         # log.write("ALERTED! Object: " + str(obj_trust) + ".Subject: " + str(subj_trust) + ".\n")
#         if orig_sip not in self.terminated:
#             self.terminated[orig_sip] = dict()
#         if orig_sport not in self.terminated[orig_sip]: 
#             log.write("Terminated connection.")
#             # Dummy value for termination
#             self.terminated[orig_sip][orig_sport] = 0
#             terminate_connection(orig_sip,orig_sport)

# def terminate_connection(ip,port):
#     # Could change this script to only search the namespaces of the relevant services.
#     print("Terminating connection on " , ip , " <-> " , port)
#     output = subprocess.run(["../../scripts/terminate.sh"]+[ip,port])
# p = PrioQ()
# p.add([1,"1"])
# print(p)
# p.add([3,"2"])
# print(p)

# p.add([5,"3"])
# print(p)

# p.add([4,"4"])
# print(p)

# p.add([4,"1"])
# print(p)

# p.add([6,"6"])
# print(p)

# print(p.more_recent(10))