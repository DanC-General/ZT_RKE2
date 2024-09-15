from argparse import ArgumentParser
import time
import numpy as np
import matplotlib.pyplot as plt
from analysis_funcs import *

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
    results.get_stats()
    # results.get_visuals("ztrke2_31_8")
    # print("Total negatives:",results.neg,"\nTotal positives:",results.pos)
    # print("True positives",results.correct_pos,"False postives", results.pos-results.correct_pos,"True negatives",results.true_neg,"False negatives",results.neg-results.true_neg)
    # print(results.total_count)
    # print([str(x) for x in atks.all])
    # get_average_atk_delay(atks)
    # all_groups,ztrke2_metrics = get_groups_from_analyser(results,atks)
    # print("ANALYSER COUNT",results.total_count)
    # zt_rke2_group = get_group_times(all_groups,results.start_time)
    print("\nRunning Kitsune comparison...")
    comp_analyser = analyse_comparison(args.comparison_file,atks)
    comp_analyser.start_time = stime
    comp_analyser.get_stats()
    # comp_analyser.get_visuals("comparison_nids_31_8")


    # for i in 
    # comp_groups, comp_metrics = get_groups_from_analyser(comp_analyser,atks)
    # print("ANALYSER COUNT",comp_analyser.total_count)
    # kit_group = get_group_times(comp_groups,results.start_time)
    # print("ZT_RKE2 METRICS",ztrke2_metrics,"COMP METS",comp_metrics)
    # print("ZT_RKE2 GROUPS")
    # for i in all_groups: 
    #     print("(( ",i,end=" ))")
    # print("COMPARISON GROUPS")
    # for i in kit_group: 
    #     print("(( ",i,end=" ))")
    # from 22:15 to 23:05 
    # Create the line plot
    # values = range(0, 3600)
    # ground_truths = dict()
    # for atk in atks.all: 
    #     ground_truths[int(atk.start_time() - results.start_time)] = atk.get_class()
    # # Create a list to store the corresponding values
    # plot_values = []
    # net_atks = []
    # host_atks = []
    # all_atks = []
    # comp_vals = []
    # for value in values:
    #     if any(start <= value <= end for start, end in zt_rke2_group):
    #         plot_values.append(1)
    #     else:
    #         plot_values.append(None)
    #     if any(start <= value <= end for start, end in kit_group):
    #         comp_vals.append(1.25)
    #     else:
    #         comp_vals.append(None)

    #     if value in ground_truths:
    #         all_atks.append(0.25)
    #         if ground_truths[value] == "Network": 
    #             net_atks.append(0.75)
    #             host_atks.append(None)
    #         else: 
    #             host_atks.append(0.5)
    #             net_atks.append(None)
    #     else:
    #         net_atks.append(None)
    #         all_atks.append(None)
    #         host_atks.append(None)

    # # print("Values",plot_values)
    # plt.figure(figsize=(20,10))
    # plt.plot(values, plot_values, drawstyle='steps-post',markersize=3,marker='o',label="Detected Attacks")
    # plt.plot(values, host_atks, drawstyle='steps-post',color="orange",markersize=3,marker='o',label="Host Attacks")
    # plt.plot(values, all_atks, drawstyle='steps-post',color="green",markersize=3,marker='o',label="All Attacks")
    # plt.plot(values, net_atks, drawstyle='steps-post',color="red",markersize=3,marker='o',label="Network Attacks")
    # plt.plot(values, comp_vals, drawstyle='steps-post',color="purple",markersize=3,marker='o',label="General model")
    # plt.xlabel("Time since start (seconds)")

    # plt.ylabel("Attack Category")
    # plt.xticks(np.arange(0,3600,step=600))
    # plt.yticks(np.arange(0,2,step=0.5))
    # plt.legend()
    # plt.title("Analysis of ZT-RKE2 model")
    # plot_time = time.strftime("%Y%m%d-%H%M%S")
    # plt.savefig(f'out/visual_31_8_{plot_time}.png')
    # # plt.show()



    # index = np.arange(4)
    # bar_width = 0.35

    # fig, ax = plt.subplots()
    # ztrke2 = ax.bar(index, ztrke2_metrics, bar_width,
    #                 label="ZTRKE2")

    # comparison = ax.bar(index+bar_width, comp_metrics,
    #                 bar_width, label="Comparison")
    # ax.set_xlabel('Metric')
    # ax.set_ylabel('Proportion')
    # ax.set_title('Incident Detection Rates by Different Models')
    # ax.set_xticks(index + bar_width / 2)
    # ax.set_xticklabels(["TP", "FP", "TN", "FN"])
    # ax.legend()
    # plt.savefig(f'out/metrics_31_8_{plot_time}.png')
    # plt.show()

if __name__ == "__main__": 
    # analyse_comparison("../module/Kit_Agent/50k_minimal.log")
    main()
    