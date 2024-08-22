import paramiko
import random
import uuid
import time
import os
from prof import make_weights
erd_cmds = ["cat","head","tail","file"]
ewr_cmds = ["cp","mv","echo \"Test string\" >","echo \"Test string\" >>","echo \"Test string\" | tee","touch"]
eed_cmds = ["sed -i 's/.*/Content has been removed./g'", "tr -s [:space:]","rm","chmod +x"]
esrch_mv_cmds = ["cd", "ls","la","which", "whereis", "grep .*", "find / -name","pwd"]
# Other executable commands
exe_cmds = ["clear","ping google.com -c 1","ip a","ps", "ss", "jobs","apt update"]
class SSHClient: 
    def __init__(self): 
        self.host = os.environ.get('IP')
        self.username = "root"
        self.password = "test"
        self.client = paramiko.client.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(self.host, username=self.username, password=self.password, port=30002)

    def run_command(self, cmd):
        _stdin, _stdout,_stderr = self.client.exec_command(cmd)
        # print(_stdout.read().decode())
        return _stdin, str(_stdout.read().decode()), _stderr

    def get_random(self): 
        _,out,_ = self.run_command("ls /tmp/`ls /tmp | sort -R | head -n 1`")
        return out.strip()
    
    def make_random_fname(self): 
        return  "/tmp/" + str(uuid.uuid4()) 

    def write_file(self):
        rcmd = random.choice(ewr_cmds)
        if rcmd == "cp" or rcmd == "mv":
            rcmd += " " + self.get_random() + " " + self.make_random_fname()
        else: 
            rcmd += " " + self.make_random_fname()
        self.run_command(rcmd)
    
    def read_file(self):
        rcmd = random.choice(erd_cmds) + " " + self.get_random()
        print(rcmd)
        self.run_command(rcmd)
    
    def exec_cmd(self): 
        self.run_command(random.choice(exe_cmds))

    def edit_file(self): 
        rcmd = random.choice(eed_cmds) + " " + self.get_random()
        print(rcmd)

    def search_mv(self): 
        rcmd = random.choice(esrch_mv_cmds) 
        if rcmd == "cd":
            rcmd = "cd .."
        else: 
            rcmd += " " + self.get_random()
        print(rcmd)
        self.run_command(rcmd)

    def exit(self):
        self.client.close()

    def simulate_one_action(self, probs = make_weights): 
        print(probs)
        options = [self.write_file,self.read_file,self.edit_file,self.search_mv,self.exec_cmd]
        res = random.choices(options, weights=probs, k=1)
        print(res)

    def simulate_x(self,num):
        for i in range(num): 
            self.simulate_one_action()

    def simulate_for_x(self,nsecs):
        start_time = time.time()
        while (time.time() - start_time < nsecs):
            continue
        print(time.time() - start_time, "elapsed.")


def main(): 
    if os.environ.get('IP') == None: 
        print("$IP not set. Set to the IP of the remote host and rerun.")
    client = SSHClient()
    # client.run_command("ls -al")
    # client.run_command("for i in {0..5}; do echo $i; done")
    # client.edit_file()
    # client.simulate_for_x(5)
    print(client.get_random())
    


if __name__ == "__main__": 
    main()