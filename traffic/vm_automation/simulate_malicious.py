import ssh_model as ssh
if __name__ == "__main__": 
    client = ssh.SSHClient()
    res = input("f for flood, b for bruteforce").lower()
    arr = ["f","b","c","s"]
    if res in arr: 
        client.run_malicious(res)
        
