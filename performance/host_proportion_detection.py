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
with open(args.file,'r') as f: 
    for line in f: 
        if line.startswith("Attack file"):
            # print(line)
            if host_only_count != 0:
            # if total_count != 0: 
                # print(host_only_count,host_count,total_count,host_only_count/total_count,host_count/total_count)
                all_results.append([host_only_count,host_count,total_count,host_only_count/total_count,host_count/total_count])
            host_only_count = 0
            host_count = 0
            net_count = 0
            total_count = 0
        line = line.strip()
        det = line.split(",")
        if det[-1] == "HOST":
            total_count += 1
            if float(det[-2]) < 0.4:
                host_only_count += 1 
            if float(det[-3]) != 1: 
                host_count += 1
                
        # FP
        # if det[-1] == "FP":
        #     total_count += 1
        #     if float(det[-2]) > 0.4:
        #         net_count += 1 
        #     if float(det[-3]) < 1: 
        #         host_count += 1
    # print(host_only_count,host_count,total_count,host_only_count/total_count,host_count/total_count)
    # print(net_count,host_count,total_count,net_count/total_count,host_count/total_count)

    print("Only subject trust:",np.mean([x[-2] for x in all_results]))
    print("Lowered subject trust:",np.mean([x[-1] for x in all_results]))