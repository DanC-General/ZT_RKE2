from argparse import ArgumentParser
import time
import numpy as np
import matplotlib.pyplot as plt
from analysis_funcs import *
import copy
#### python3 analyse_log.py 31_8_py.log -a 31_8_mal.log -c ../module/Kit_Agent/100k_minimal.log
#### python3 analyse_log.py v2_14_9_py.log -a v2_14_9_mal.log -c ../module/Kit_Agent/14_9_100_minimal.log
#### pcapsampler -m COUNT_RAND_UNIFORM -r x input.pcap output.pcap
def main(): 
    parser = ArgumentParser()
    parser.add_argument("file", help="Path of file to anlayse")
    parser.add_argument("-a","--attack-file",help="Path of file containing the attack logs")
    parser.add_argument("-c","--comparison-file",help="Path of file containing the parsed data for Kitsune output")
    args = parser.parse_args()
    stime = get_start_time(args.file)
    atks = parse_attack_file(args.attack_file,stime)
    # print("Attacks", [x for x in atks.all])
    results = parse_log_file(args.file,atks)
    print("\nRunning ZT_RKE2 model...")
    show_results(results.get_stats())
    results.get_visuals(args.file+"_ztrke2",True)

    highest_f1 = 0
    highest_stats = []
    highest_rmse = 0
    best_comp = None
    print("\nRunning Kitsune comparison...")
    for i in [x / 10.0 for x in range(1, 10, 1)]:
        comp_analyser = analyse_comparison(args.comparison_file,atks,rmse_val=i)
        comp_analyser.start_time = stime
        stats = comp_analyser.get_stats()
        f1 = stats[-3]
        # print("\nRMSE",i,f1,"\n")
        if f1 > highest_f1: 
            highest_f1 = f1
            highest_stats = stats
            highest_rmse = i
            best_comp = copy.deepcopy(comp_analyser)
    # print("t_p,f_p,t_n,f_n,acc,prec,rec,f1,net_det,host_det")
    # print(f"At RMSE {highest_rmse}:")
    show_results(highest_stats)

    best_comp.get_visuals(args.comparison_file+"_kitsune",False)

def show_results(stats): 
    print(f"    ACC: {stats[4]}, PREC: {stats[5]}, REC: {stats[6]}, F1: {stats[7]}\n")
    # print(f"t_p: {stats[0]},f_p: {stats[1]},t_n: {stats[2]},f_n: {stats[3]},acc: {stats[4]},prec: {stats[5]},rec: {stats[6]},f1: {stats[7]},net_det: {stats[8]},host_det : {stats[9]}")

if __name__ == "__main__": 
    # analyse_comparison("../module/Kit_Agent/50k_minimal.log")
    main()
    