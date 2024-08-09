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
        if not self.full(): 
            self.store.append(item)
        else: 
            for i in self.store:
                # Added items will have newer timestamps, 
                #   so should update that timestamp
                if item[1] == i[1]:
                    i[0] == item[0]
                    self.store.sort()
                    return
            # Greater ts -> newer packet. 
            if item[0] > self.store[0][0]: 
                self.store[0] = item
        self.store.sort()
    def more_recent(self,ts):
        rec = list()
        ts = float(ts)
        for i in self.store: 
            print(ts, "<->",i[0])
            delta = (ts - 5) - i[0]
            if i[0] >= ts - 5: 
                print(i[1], " has relevant delta",delta,": added!")
                rec.append(i[1])
        rec.reverse()
        return rec
    def empty(self): 
        return len(self.store) == 0
    def full(self):
        return len(self.store) == 3
    def contains(self, str):
        for i in self.store: 
            if i[1] == str:
                return True
        return False 
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