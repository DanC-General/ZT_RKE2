import ssh_model as ssh
if __name__ == "__main__": 
    client = ssh.SSHClient()
    res = input("f for flood, b for bruteforce,s for symlink,c for dirtycow").lower()
    # arr = ["f","b","c","s"]
    # if res in arr: 
    #     client.run_malicious(res)
    # while True: 
    client.add_malicious(res)
