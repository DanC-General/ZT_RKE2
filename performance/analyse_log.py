from argparse import ArgumentParser
import matplotlib.pyplot as plt
import datetime
import math
import numpy as np
import os
import re
import time
import statistics
from analysis_cls import Analyser,Attacks,Attack,Request,timestr_to_obj

def analyse_comparison(file_name):
    if not os.path.exists(file_name): 
        print("Invalid file for comparison.")
        return
    results = Analyser()
    with open(file_name,'r') as f:
        for line in f:
            results.analyse_comp_line(line)
    # print(results.req_q)
    # all_grps = get_groups_from_analyser(results)
    return results

def get_group_times(group_list,start_time): 
    atk_ranges = list()
    for grp in group_list:
        # print("Group",grp)
        start = grp[1] - start_time
        end = grp[2] -  start_time
        atk_ranges.append((int(start),int(end)))
    return atk_ranges

def get_groups_from_analyser(results,atks,start_time):
    groups = dict()
    count = 0
    fal_pos = 0
    true_pos = 0
    values = {"total":0,"within_90s":0,"correct_host":0}
    all_groups = list()
    host_list = []
    for r in results.req_q:
        near = atks.get_host_atks(r)
        host_str = ""
        for i,v in enumerate(sorted(r.hosts)):
            host_str += "-" + str(v)

        ##### GROUP COUNTING NOT WORKING PROPERLY #####


        if host_str not in host_list: 
            host_list.append(host_str)
        if host_str in groups:
            # print(host_str)
            # found = True
            groups[host_str][0] += 1
            # If there is a gap larger than 60 seconds between packets, end the current flow.
            if r.ts - groups[host_str][2] > 60:
                ### Terminate an old group
                if len(groups[host_str]) > 4:
                    groups[host_str][6] = to_date(groups[host_str][6])
                all_groups.append(groups[host_str].copy())
                values["total"] += 1
                if groups[host_str][3] is None:
                # if near[0] is None: 
                    fal_pos += groups[host_str][0]
                # elif near[0] < 90: 
                elif groups[host_str][3] < 60:
                # else:
                    true_pos += groups[host_str][0]
                    # print("Incremented",near[1],r)
                else:
                    fal_pos += groups[host_str][0]
                # count += 1
                groups[host_str] = [0,r.ts,r.ts,near[0],near[1].name,near[1].host,near[1].ts,r.hosts,near[1].id]                         
            else: 
                groups[host_str][2] = r.ts 
        # if not found:
        else:
            ## Start a new group
            groups[host_str] = [0,r.ts,r.ts,near[0],near[1].name,near[1].host,near[1].ts,r.hosts,near[1].id]      

    ## END UNTERMIANTED GROUPS
    for host_str,group in groups.items():
        # print("GROUPS",host_str,group)
        all_groups.append(group.copy())
        if group[3] is None:
        # if near[0] is None: 
            fal_pos += group[0]
        # elif near[0] < 90: 
        elif group[3] < 60:
        # else:
            true_pos += group[0]
            # print("Incremented",near[1],r)
        else:
            fal_pos += group[0]
    print("A_G:",all_groups)
    # print("C_G",groups)
    ids = []
    for grp in all_groups:
        if grp[8] not in ids:
            print(grp[8],datetime.datetime.fromtimestamp(grp[0]).time(),grp[7])
            ids.append(grp[8])
        else:
            print("Duplicate",grp[8],datetime.datetime.fromtimestamp(grp[0]).time(),grp[7])
            print(atks.get_60s_ts(float(r.ts) + float(start_time),grp[7]))
    for atk in atks.all: 
        if atk.id not in ids:
            print("Missing",atk)
        
    count = results.total_count
    total_pos = fal_pos + true_pos
    print("PARSED ", count, "packets")
    print("LISTS",host_list)
    print("IDS",len(ids),ids)
    print("COUNTS", count, "FP",fal_pos,"prop FP",fal_pos/total_pos,"TP",true_pos,"prop",true_pos/total_pos)
    return all_groups

def to_date(times):
    if times is not None:
        return str(datetime.datetime.fromtimestamp(float(times)).time()) 

def parse_attack_file(file,start):
    atks = Attacks()
    if file is not None:
        print("Attack file given at",file)
        with open(file,"r") as atk_f: 
            host="LOCAL"
            for line in atk_f:
                # print("ATK LINE",line)
                if "##" in line: 
                    if "ORDERED" in line: 
                        break
                    host = line.replace("##","").strip()
                try:
                    one = line.split('at')
                    ts = one[1]
                    two = one[0].split('malicious')
                    atk = two[1]
                    host = host 
                    atk_details = Attack(atk.strip(),ts.strip(),host.strip())
                    if atk_details.is_newer(start):
                        # print(atk_details)
                        atks.add_attack(atk_details)
                    # print("Parsed ts:",ts.strip(),"atk:",atk.strip(),"host",host)
                except:
                    pass
    else: 
        return
    atks.order()
    # for i in atks.all: 
    #     print("((",i,end=")),  ")
    # print("Found",len(atks.all),"attacks")
    return atks
    
def parse_log_file(fname):
    print(fname) 
    with open(fname,"r") as raw: 
        results = Analyser()
        line = raw.readline()
        print("|st",timestr_to_obj(line))
        results.set_start(line)        
        for line in raw: 
            # print(line)
            results.analyse_line(line,raw)
        return results

def get_average_atk_delay(atks):
    objs = []
    prev = None
    for i in atks.all: 
        cur = i.ts
        if prev is None: 
            prev = cur
            continue
        objs.append(cur-prev)
        prev = cur
    print(objs)
    print("Average delay",statistics.fmean(objs),statistics.median(objs))

def main(): 
    parser = ArgumentParser()
    parser.add_argument("file", help="Path of file to anlayse")
    parser.add_argument("-a","--attack-file",help="Path of file containing the attack logs")
    args = parser.parse_args()
    results = parse_log_file(args.file)
    atks = parse_attack_file(args.attack_file,results.start_time)
    get_average_atk_delay(atks)
    all_groups = get_groups_from_analyser(results,atks,results.start_time)
    print("ANALYSER COUNT",results.total_count)
    zt_rke2_group = get_group_times(all_groups,results.start_time)
    comp_analyser = analyse_comparison("../module/Kit_Agent/100k_minimal.log")
    print("ANALYSER COUNT",comp_analyser.total_count)
    comp_groups = get_groups_from_analyser(comp_analyser,atks,results.start_time)
    kit_group = get_group_times(comp_groups,results.start_time)
    # print("ZT_RKE2 GROUPS")
    # for i in all_groups: 
    #     print("(( ",i,end=" ))")
    # print("COMPARISON GROUPS")
    # for i in kit_group: 
    #     print("(( ",i,end=" ))")
    # from 22:15 to 23:05 
    # Create the line plot
    values = range(0, 3600)
    ground_truths = dict()
    for atk in atks.all: 
        ground_truths[int(atk.ts - results.start_time)] = atk.get_class()
    # Create a list to store the corresponding values
    plot_values = []
    net_atks = []
    host_atks = []
    all_atks = []
    comp_vals = []
    for value in values:
        if any(start <= value <= end for start, end in zt_rke2_group):
            plot_values.append(1)
        else:
            plot_values.append(None)
        if any(start <= value <= end for start, end in kit_group):
            comp_vals.append(1.25)
        else:
            comp_vals.append(None)

        if value in ground_truths:
            all_atks.append(0.25)
            if ground_truths[value] == "Network": 
                net_atks.append(0.75)
                host_atks.append(None)
            else: 
                host_atks.append(0.5)
                net_atks.append(None)
        else:
            net_atks.append(None)
            all_atks.append(None)
            host_atks.append(None)

    # print("Values",plot_values)
    plt.figure(figsize=(20,10))
    plt.plot(values, plot_values, drawstyle='steps-post',markersize=3,marker='o',label="Detected Attacks")
    plt.plot(values, host_atks, drawstyle='steps-post',color="orange",markersize=3,marker='o',label="Host Attacks")
    plt.plot(values, all_atks, drawstyle='steps-post',color="green",markersize=3,marker='o',label="All Attacks")
    plt.plot(values, net_atks, drawstyle='steps-post',color="red",markersize=3,marker='o',label="Network Attacks")
    plt.plot(values, comp_vals, drawstyle='steps-post',color="purple",markersize=3,marker='o',label="General model")
    plt.xlabel("Time since start (seconds)")

    plt.ylabel("Attack Category")
    plt.xticks(np.arange(0,3600,step=600))
    plt.yticks(np.arange(0,2,step=0.5))
    plt.legend()
    plt.title("Analysis of ZT-RKE2 model")
    # plt.savefig(f'out/31_8_{time.strftime("%Y%m%d-%H%M%S")}.png')
    # plt.show()


if __name__ == "__main__": 
    # analyse_comparison("../module/Kit_Agent/50k_minimal.log")
    main()
    