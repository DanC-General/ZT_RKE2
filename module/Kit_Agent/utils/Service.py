from Kitsune import Kitsune
import subprocess
from .DataStructs import PrioQ, StatTracker
class Service: 
    def __init__(self,maxAE,FMgrace,ADgrace,name,port): 
        self.subj_sysc_map = dict()
        self.prev_subj = PrioQ()
        self.terminated = dict()
        self.ml = Kitsune(None,None,maxAE,FMgrace,ADgrace)
        self.stats = StatTracker()
        self.name = name
        self.port = port

    def total_abnormal(self): 
        total = 0
        for subject in self.subj_sysc_map: 
            if "total" in self.subj_sysc_map[subject]:
                total += self.subj_sysc_map[subject]["total"]
        return total
    
    def handle_alert(self,syscall,alert_ts,log): 
        # print("Recieved an alert!!")
        # print(item)
        log.write(syscall + str(alert_ts) + "\n")
        recency = 5
        # Change to use alert ts
        for subject in self.prev_subj.more_recent(alert_ts): 
            print("Adding to malicious", subject)
            # if subject not in subj_sysc_map: 
            #     subj_sysc_map[subject] = dict()
            # else: 
            #     # if "total" not in subj_sysc_map[subject]: 
            #     #     subj_sysc_map[subject]["total"] = 1 * recency
            self.subj_sysc_map[subject]["total"] += 1 * recency
            if syscall not in self.subj_sysc_map[subject]:
                self.subj_sysc_map[subject][syscall] = 1 * recency
            else:
                self.subj_sysc_map[subject][syscall] += 1 * recency
            # Update so next subject is less recent
            recency -= 2
        log.write(self.name + ":: " + str(self.subj_sysc_map) + "\n")

    def add_recent(self,subject,time): 
        cur_sysc_map = self.subj_sysc_map
        if subject not in cur_sysc_map: 
            cur_sysc_map[subject] = dict()
            print("Map did not contain ", subject)
        if "total" not in cur_sysc_map[subject]: 
            cur_sysc_map[subject]["total"] = 0
            print(subject, "did not contain total")

        if not self.prev_subj.contains(subject):
            print("APPENDING ", subject, "to ",self.name, "\n")
            self.prev_subj.add((time,subject))
            print(self.prev_subj)
        
    def subject_trust(self,subject,cur_call,log):
        subj_trust = -1
        total_ab_sys = self.total_abnormal()
        smap = self.subj_sysc_map
        if smap[subject]["total"] > 0 and total_ab_sys > 0 :
            print("Set subject trust to ", smap[subject]["total"],"/",total_ab_sys," = ",int(smap[subject]["total"])/int(total_ab_sys))
            subj_trust = int(smap[subject]["total"])/int(total_ab_sys)
            log.write("Subject trust for " + subject + ": " + str(subj_trust) + "\n")
            if cur_call in smap: 
                if smap[subject][cur_call] != 1: 
                    print("Repeat syscall ",cur_call, ", skipping.")
                    subj_trust = -1
        smap[subject]["trust"] = subj_trust
        log.write(self.name + ":: " + str(self.subj_sysc_map) + "\n")
        return subj_trust
    
    def terminate(self,orig_sip,orig_sport,log):
        # log.write("ALERTED! Object: " + str(obj_trust) + ".Subject: " + str(subj_trust) + ".\n")
        if orig_sip not in self.terminated:
            self.terminated[orig_sip] = dict()
        if orig_sport not in self.terminated[orig_sip]: 
            log.write("Terminated connection.")
            # Dummy value for termination
            self.terminated[orig_sip][orig_sport] = 0
            terminate_connection(orig_sip,orig_sport)

def terminate_connection(ip,port):
    # Could change this script to only search the namespaces of the relevant services.
    print("Terminating connection on " , ip , " <-> " , port)
    output = subprocess.run(["../scripts/terminate.sh"]+[ip,port])
