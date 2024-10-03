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
is_ztrke2 = False
cat_counts = list()
# host_only_count = 0
# host_count = 0
# net_count = 0
# total_count = 0
# all_results = []
# fp_results = []
# fp_count = 0
# both_fp = 0
# host_fp = 0
# net_fp = 0
class Metric(): 
    def __init__(self,name): 
        self.results = []
        self.name = name
        self.total_count = 0
        self.both_count = 0
        self.host_count = 0
        self.net_count = 0
    def reset(self):
        self.total_count = 0
        self.both_count = 0
        self.host_count = 0
        self.net_count = 0
    def get_results(self): 
        # [s for s in self.results: ]
        arr = list()
        for i in range(0,3):
            arr.append((float(np.mean([x[i]/x[-1] for x in self.results]))))
        return arr
# Host TP, Net TP, All FP 
metrics = {"NET": Metric("NET"),"HOST":Metric("HOST"),"FP": Metric("FP")}
with open(args.file,'r') as f: 
    for line in f: 
        if line.startswith("Running ZT_RKE2"):
            is_ztrke2 = True
        elif line.startswith("Running Kitsune"):   
            is_ztrke2 = False

        if line.startswith("    HOST"):
            det = line.strip().split(" ")
            if not is_ztrke2: 
                print("ZTRKE2",det)
                cat_counts.append([det[1],det[3]])
        if line.startswith("Attack file"):
            # print(line)
            for k,m in metrics.items(): 
                if m.host_count != 0: 
                    m.results.append([m.host_count,m.both_count,m.net_count,m.total_count])
                m.reset()
        line = line.strip()
        det = line.split(",")
        if det[-1] == "NET" or det[-1] == "HOST":
            metrics[det[-1]].total_count += 1
            add = False
            if float(det[-2]) < 0.4:
                metrics[det[-1]].host_count += 1 
                add = True
            if float(det[-3]) != 1: 
                metrics[det[-1]].both_count += 1
                add = True
            if not add: 
                metrics[det[-1]].net_count += 1 

                
        # FP
        if det[-1] == "FP":
            metrics["FP"].total_count += 1
            # if float(det[-2]) > 0.2 and float(det[-3]) < 0.7:
            #     metrics["FP"].both_count += 1
            # elif float(det[-2]) > 0.4:
            #     metrics["FP"].net_count += 1 
            # # elif float(det[-3]) < 0.5: 
            # else:
            #     metrics["FP"].host_count += 1
            metrics["FP"].total_count += 1
            if float(det[-3]) < 1: 
                if float(det[-2]) < 0.4:
                    metrics["FP"].host_count += 1
                else:
                    metrics["FP"].both_count += 1
            elif float(det[-2]) > 0.4: 
                metrics["FP"].net_count += 1 
    # print(host_only_count,host_count,total_count,host_only_count/total_count,host_count/total_count)
    # print(net_count,host_count,total_count,net_count/total_count,host_count/total_count)
    print([[k,v.get_results()] for k,v in metrics.items()])
#     print("Host mean",statistics.mean(list([float(x[0].replace(",","")) for x in cat_counts if float(x[0].replace(",","")) !=  0.5])))
#     print("Net mean",statistics.mean(list([float(x[1].replace(",","")) for x in cat_counts if float(x[1].replace(",","")) !=  0.5]))
# )
#     print("Host averages",statistics.mean([float(x[0].replace(",","")) for x in cat_counts if x[0] !=  0.5]),"network averages",np.mean([x[1] for x in cat_counts]))

    # subj_only = np.mean([x[-2] for x in all_results])
    # both = np.mean([x[-1] for x in all_results])
    # print("Only subject trust:",np.mean([x[-2] for x in all_results]))
    # print("Lowered subject trust:",np.mean([x[-1] for x in all_results]))
    # p_fp_host = np.mean([x[0]/x[-1] for x in fp_results])
    # p_fp_net = np.mean([x[1]/x[-1] for x in fp_results])
    # p_fp_both = np.mean([x[2]/x[-1] for x in fp_results])
    # print("Host FP:",np.mean([x[0]/x[-1] for x in fp_results]))
    # print("Net FP:",np.mean([x[1]/x[-1] for x in fp_results]))
    # print("Combined FP:",np.mean([x[2]/x[-1] for x in fp_results]))
    hres = metrics["HOST"].get_results()
    nres = metrics["NET"].get_results()
    fpres = metrics["FP"].get_results()
    df = pd.DataFrame([
                        ['Host TP',hres[0],hres[1]-hres[0],1-hres[1]],
                        ["Net TP",nres[0],nres[1]-nres[0],1-nres[1]],
                        # ['All FP',fpres[0],fpres[1]-fpres[0],1-fpres[1]]
                      ],
                      columns=["Packet Label","Subject Alert","Both","Object Alert"],
    )
    df.plot(stacked=True,x="Packet Label",kind='bar',rot=0,title="Trust Component Roles in True Positives")
    plt.savefig("Trust_Roles_TP.png")
    plt.show()
    df = pd.DataFrame([
                        ['All FP',fpres[0],fpres[1]-fpres[0],1-fpres[1]]
                      ],
                      columns=["Packet Label","Subject Alert","Both","Object Alert"],
    )
    df.plot(figsize=(4,5),stacked=True,x="Packet Label",kind='bar',rot=0,width=0.2,title="Trust Component Roles in False Positives")
    plt.savefig("Trust_Roles_FP.png")
    plt.show()