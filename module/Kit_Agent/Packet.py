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
        self.ts = float(props[7])
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
        