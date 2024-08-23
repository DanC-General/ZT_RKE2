import paramiko
import random
import uuid
import time
import os
import prof
erd_cmds = ["cat","head","tail","file"]
ewr_cmds = ["cp","mv","echo \"Test string\" >","echo \"Test string\" >>","echo \"Test string\" | tee","touch"]
eed_cmds = ["sed -i 's/.*/Content has been removed./g'", "tr -s [:space:] <","rm","chmod +x"]
esrch_mv_cmds = ["cd", "ls","la","which", "whereis", "grep .*", "find / -name","pwd"]
# Other executable commands
exe_cmds = ["clear","ping google.com -c 1","ip a","ps", "ss", "jobs"]
transition_matrix =  [
    [30.985915492957744, 1.056338028169014, 6.690140845070422, 38.028169014084504, 23.239436619718308], 
    [2.4242424242424243, 39.696969696969695, 3.939393939393939, 30.303030303030305, 23.636363636363637], 
    [3.864734299516908, 2.4154589371980677, 26.08695652173913, 44.20289855072464, 23.42995169082126], 
    [5.339578454332552, 4.496487119437939, 9.695550351288055, 58.922716627634664, 21.54566744730679], 
    [3.1161473087818696, 4.645892351274788, 3.6260623229461753, 27.138810198300284, 61.47308781869688]
]
states = {"read":0,"write":1,"edit":2,"search":3,"exe":4}
first_actions = [3.0927835051546393, 0.0, 6.185567010309279, 55.670103092783506, 35.051546391752574]
general_distributions = [5.321610365571495, 7.380842202683943, 7.7279037482646915, 44.863489125404904, 34.706154558074964]
class SSHClient: 
    def __init__(self): 
        self.host = os.environ.get('IP')
        self.username = "root"
        self.password = "test"
        # self.probs = prof.make_weights()
        self.count = 0
        self.probs = [7.565941693660343, 11.938917167977788, 20.43035631652013, 29.40768162887552, 30.65710319296622]
        self.client = paramiko.client.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(self.host, username=self.username, password=self.password, port=30002)
        self.options = [self.write_file,self.read_file,self.edit_file,self.search_mv,self.exec_cmd]


    def run_command(self, cmd):
        _stdin, _stdout,_stderr = self.client.exec_command(cmd)
        out = _stdout.read().decode()
        return _stdin, out, _stderr

    def get_next(self,state):
        return random.choices(self.options, weights=transition_matrix[state],k=1)[0]

    def get_random(self): 
        _,out,_ = self.run_command("ls /tmp/`ls /tmp | sort -R | head -n 1`")
        return out.strip()
    
    def make_random_fname(self): 
        return  "/tmp/" + str(uuid.uuid4()) 

    def run_action(self,func):
        self.count += 1
        if (self.count < 53):
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
        # self.run_command(rcmd)
        print(rcmd)
        next_action = self.get_next(state)
        self.run_action(next_action)

    def read_file(self):
        state = states["read"]
        rcmd = random.choice(erd_cmds) + " " + self.get_random()
        # print(rcmd)
        # self.run_command(rcmd)
        print(rcmd)
        next_action = self.get_next(state)
        self.run_action(next_action)    

    def exec_cmd(self): 
        state = states["exe"]
        rcmd = random.choice(exe_cmds)
        # self.run_command(rcmd)
        print(rcmd)
        next_action = self.get_next(state)
        self.run_action(next_action)

    def edit_file(self): 
        state = states["edit"]
        rcmd = random.choice(eed_cmds) + " " + self.get_random()
        # print("RCMD is " ,rcmd)
        # self.run_command(rcmd)
        print(rcmd)
        next_action = self.get_next(state)
        self.run_action(next_action)

    def search_mv(self): 
        state = states["search"]
        rcmd = random.choice(esrch_mv_cmds) 
        if rcmd == "cd":
            rcmd = "cd .."
        else: 
            rcmd += " " + self.get_random()
        # print(rcmd)
        # self.run_command(rcmd)
        print(rcmd)
        next_action = self.get_next(state)
        self.run_action(next_action)

    def exit(self):
        self.count = 0
        self.run_command("exit") 
        self.client.close()

    # def simulate_one_action(self, probs = [0.2,0.2,0.2,0.2,0.2]):
    #     probs = self.probs
    #     res = random.choices(self.options, weights=probs, k=1)
    #     print(res)
    #     res[0]()

    # def simulate_x(self,num):
    #     for i in range(num): 
    #         self.simulate_one_action()

    # def simulate_for_x(self,secs):
    #     start_time = time.time()
    #     while (time.time() - start_time < secs):
    #         self.simulate_one_action()
    #         continue
    #     print(time.time() - start_time, "elapsed.")
    
    def simulate_session(self): 
        # self.simulate_x(num)
        first = random.choices(self.options,weights=first_actions)[0]
        first()
        self.client = paramiko.client.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(self.host, username=self.username, password=self.password, port=30002)


def main(): 
    if os.environ.get('IP') == None: 
        print("$IP not set. Set to the IP of the remote host and rerun.")
    client = SSHClient()
    client.simulate_session()
    client.simulate_session()
    # client.run_command("ls -al")
    # client.run_command("for i in {0..5}; do echo $i; done")
    # client.edit_file()
    # client.simulate_x(5)
    # client.simulate_one_action()
    # client.simulate_for_x(5)
    # print(client.get_random())
    


if __name__ == "__main__": 
    main()