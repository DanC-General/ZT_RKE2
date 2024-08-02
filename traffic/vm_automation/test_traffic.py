import subprocess
from random import shuffle
import os
files = dict()

def randomly_run(): 
    for svc in files:
        file_list = files[svc]
        print("SVC: ",svc, " FLIST: ", file_list)
        shuffle(file_list)
        for file in file_list: 
            try: 
                print("Running ", file)
                subprocess.call(file)
            except Exception as err: 
                print("Got some error: ", err)
                continue
        

def main(): 
    global files
    if os.environ.get('IP') == None: 
        print("$IP not set. Set to the IP of the remote host and rerun.")
    output = subprocess.run("./randomise.sh",capture_output=True,universal_newlines=True)
    arr = output.stdout.split("\n")
    for i in arr: 
        if i == "": 
            continue
        det = i.split(":")
        print(det)
        if det[0] not in files:
            files[det[0]] = list()
        files[det[0]].append(det[1])
    print(files)
    randomly_run()

if __name__ == "__main__":
    main()