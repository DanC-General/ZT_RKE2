import ssh_model as ssh
if __name__ == "__main__": 
    client = ssh.SSHClient()
    res = input("f for flood, b for bruteforce")
    if res.lower() == "f": 
        client.run_malicious("f")
    elif res.lower() == "b": 
        client.run_malicious("b")
    else: 
        client.run_malicious()
        
