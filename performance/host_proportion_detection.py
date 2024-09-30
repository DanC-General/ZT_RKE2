from argparse import ArgumentParser
import statistics
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd 
parser = ArgumentParser()
parser.add_argument("file",help="Path of file to write to")
args = parser.parse_args()
kitsune = [list() for x in range(0,4)]
ztrke2 = [list() for x in range(0,4)]
host_only_count = 0
host_count = 0
net_count = 0
total_count = 0
all_results = []
fp_results = []
fp_count = 0
both_fp = 0
host_fp = 0
net_fp = 0
with open(args.file,'r') as f: 
    for line in f: 
        if line.startswith("Attack file"):
            # print(line)
            if host_only_count != 0:
            # if total_count != 0: 
                # print(host_only_count,host_count,total_count,host_only_count/total_count,host_count/total_count)
                print("Adding host",[host_only_count,host_count,total_count,host_only_count/total_count,host_count/total_count])
                all_results.append([host_only_count,host_count,total_count,host_only_count/total_count,host_count/total_count])
            if fp_count != 0: 
                print("Adding",[host_fp,net_fp,both_fp,fp_count])
                fp_results.append([host_fp,net_fp,both_fp,fp_count])
            host_only_count = 0
            host_count = 0
            net_count = 0
            total_count = 0
            fp_count = 0 
            host_fp = 0
            net_fp = 0
            both_fp = 0
        line = line.strip()
        det = line.split(",")
        if det[-1] == "HOST":
            total_count += 1
            if float(det[-2]) < 0.4:
                host_only_count += 1 
            if float(det[-3]) != 1: 
                host_count += 1
                
        # FP
        if det[-1] == "FP":
            fp_count += 1
            if float(det[-2]) > 0.2 and float(det[-3]) < 0.7:
                both_fp += 1
            elif float(det[-2]) > 0.4:
                net_fp += 1 
            # elif float(det[-3]) < 0.5: 
            else:
                host_fp += 1
    # print(host_only_count,host_count,total_count,host_only_count/total_count,host_count/total_count)
    # print(net_count,host_count,total_count,net_count/total_count,host_count/total_count)
    subj_only = np.mean([x[-2] for x in all_results])
    both = np.mean([x[-1] for x in all_results])
    print("Only subject trust:",np.mean([x[-2] for x in all_results]))
    print("Lowered subject trust:",np.mean([x[-1] for x in all_results]))
    p_fp_host = np.mean([x[0]/x[-1] for x in fp_results])
    p_fp_net = np.mean([x[1]/x[-1] for x in fp_results])
    p_fp_both = np.mean([x[2]/x[-1] for x in fp_results])
    print("Host FP:",np.mean([x[0]/x[-1] for x in fp_results]))
    print("Net FP:",np.mean([x[1]/x[-1] for x in fp_results]))
    print("Combined FP:",np.mean([x[2]/x[-1] for x in fp_results]))
    df = pd.DataFrame([['Host TP',subj_only,both-subj_only,1-both],['All FP',p_fp_host,p_fp_both,p_fp_net]],columns=["Packet Label","Subject Alert","Both","Object Alert"])
    df.plot(stacked=True,x="Packet Label",kind='bar',rot=0,title="Subject Role in Host Attack Detection")
    # df = pd.DataFrame([['Host',subj_only,1-subj_only],['Both',both,1-both]],columns=["Type","Detected","Missed"])
    # df.plot(stacked=True,x="Type",kind='bar',title="Subject Trust Efficacy")
    plt.show()