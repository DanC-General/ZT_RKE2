import paramiko
import uuid
import os

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
        print(_stdout.read().decode())

    def write_file(self):
        fname = "/tmp/" + str(uuid.uuid4()) 
        fcmd = "echo \"This is a new file\" >> " + fname
        self.run_command(fcmd)

    def read_file(self):
        rcmd = "cat /tmp/`ls /tmp | sort -R | head -n 1`"
        self.run_command(rcmd)
    
    def exec_cmd(self): 
        self.run_command("ls")
        self.run_command("find . -name '*' 2>/dev/null")

    def edit_file(self): 
        self.run_command("sed -i 's/.*/Content has been removed./g' /tmp/`ls /tmp | sort -R | head -n 1`")

    def exit(self):
        self.client.close()

def main(): 
    if os.environ.get('IP') == None: 
        print("$IP not set. Set to the IP of the remote host and rerun.")
    client = SSHClient()
    # client.run_command("ls -al")
    # client.run_command("for i in {0..5}; do echo $i; done")
    client.edit_file()
    


if __name__ == "__main__": 
    main()