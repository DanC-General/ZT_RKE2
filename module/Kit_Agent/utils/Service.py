from Kitsune import Kitsune
import subprocess
from .DataStructs import PrioQ, StatTracker
from .FuzzyLogic import SRule
class Service: 
    def __init__(self,maxAE,FMgrace,ADgrace,name,port): 
        self.subj_sysc_map = dict()
        self.prev_subj = PrioQ()
        self.terminated = dict()
        self.ml = Kitsune(None,None,maxAE,FMgrace,ADgrace)
        # TODO remove
        self.stats = StatTracker()
        self.Sfuzz = SRule()
        self.name = name
        self.port = port
        self.log = None
        self.count = 0

    def write(self,msg):
        if self.log is not None: 
            self.log.write(msg)

    def total_abnormal(self): 
        total = 0
        for subject in self.subj_sysc_map: 
            if "total" in self.subj_sysc_map[subject]:
                total += self.subj_sysc_map[subject]["total"]
        return total
    
    def reset_count(self): 
        self.write(str(self.count) + " benign packets.\n")
        self.count = 0

    def handle_alert(self,syscall,alert_ts): 
        # print("Recieved an alert!!")
        # print(item)
        # self.write(syscall +" " + str(alert_ts) + "\n")
        recency = 5
        i = 0
        # print("Handling alert for", syscall)
        # print("Previous subjects", self.prev_subj.more_recent(alert_ts))
        # Change to use alert ts
        # self.write("All subjects "+ str(self.prev_subj.store)+"\n")
        # self.write("Alert on:" + str(self.prev_subj.more_recent(alert_ts)) + "\n")
        for subject in self.prev_subj.more_recent(alert_ts): 
        
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
            self.subj_sysc_map[subject]["trust"] = self.make_trust(subject,syscall,i)
            i+=1
        # self.log.write(self.name + ":: " + str(self.subj_sysc_map) + "\n")

    def add_recent(self,subject,time): 
        cur_sysc_map = self.subj_sysc_map
        if subject not in cur_sysc_map: 
            cur_sysc_map[subject] = dict()
            print("Map did not contain ", subject)
        if "total" not in cur_sysc_map[subject]: 
            cur_sysc_map[subject]["total"] = 0
            print(subject, "did not contain total")

        # if not self.prev_subj.contains(subject):
            # print("APPENDING ", subject, "to ",self.name, "\n")
        self.prev_subj.add((time,subject))
            # print(self.prev_subj)
        
    def subject_trust(self,subject):
        if "trust" not in self.subj_sysc_map[subject]:
            self.subj_sysc_map[subject]["trust"] = 1
        # smap[subject]["trust"] = subj_trust
        # self.log.write(self.name + ":: " + str(self.subj_sysc_map) + "\n")
        return self.subj_sysc_map[subject]["trust"]
    
    def terminate(self,orig_sip,orig_sport,log):
        self.reset_count()
        # log.write("ALERTED! Object: " + str(obj_trust) + ".Subject: " + str(subj_trust) + ".\n")
        if orig_sip not in self.terminated:
            self.terminated[orig_sip] = dict()
        if orig_sport not in self.terminated[orig_sip]: 
            self.write("Terminated connection.\n")
            # Dummy value for termination
            self.terminated[orig_sip][orig_sport] = 0
            terminate_connection(orig_sip,orig_sport)

    def __get_sysc_trust(self,subject,syscall):
        smap = self.subj_sysc_map
        if syscall not in smap[subject]:
            return 0
        total = 0
        for s in smap: 
            if syscall in smap[s]: 
                total += smap[s][syscall]
        return smap[subject][syscall] / total
    
    def __get_subj_trust(self,subject):
        return int(self.subj_sysc_map[subject]["total"]) / self.total_abnormal()
    
    def make_trust(self,subject,syscall,likelihood): 
        past_st = round(self.__get_subj_trust(subject),1)
        sys_st = round(self.__get_sysc_trust(subject,syscall),1)
        return round(self.Sfuzz.simulate(likelihood,past_st,sys_st,self.log),2)

def terminate_connection(ip,port):
    # Could change this script to only search the namespaces of the relevant services.
    print("Terminating connection on " , ip , " <-> " , port)
    subprocess.run(["../scripts/terminate.sh"]+[ip,port])


