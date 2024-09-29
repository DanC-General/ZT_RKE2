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
cur_ztrke2 = True
i = 0
kit_count = 1
zt_count = 1
relevant_file = True
with open(args.file,'r') as f: 
    for line in f: 
        line = line.strip()
        # if line.startswith('Trial_Out/0-'):
        # # if line.startswith('Trial_Out/0-') or line.startswith('Trial_Out/01'):
        #     relevant_file = True
        #     pass
        # elif line.startswith('Trial_Out/0'):
        #     relevant_file = False
        #     continue
        # elif line.startswith('Trial_Out'): 
        #     relevant_file = True
        # print("COUNTS",zt_count,kit_count)
        if line.strip().startswith("ACC"):
            if not relevant_file: 
                continue
            print("COUNT:",zt_count)
            if i > 6: 
                break
            det = line.split(',')
            print("Detail ",det)
            if cur_ztrke2:
                print("Adding ztrke2")
                zt_count += 1 
            else: 
                print("Adding kitsune")  
                kit_count += 1             
            for i,item in enumerate(det):
                values = [x.strip() for x in item.split(':')]
                if cur_ztrke2:
                    ztrke2[i].append(float(values[1]))
                else: 
                    kitsune[i].append(float(values[1]))
                print(i,values)
            cur_ztrke2 = not cur_ztrke2
    print("COUNTS",zt_count,kit_count)
    print("Kitsune")
    print([statistics.mean(x) for x in kitsune])
    print("ZT_RKE2",len(ztrke2[2]))
    print([statistics.mean(x) for x in ztrke2])
    # Calculate the average
    ztrke2_means = [np.mean(x) for x in ztrke2]
    kitsune_means = [np.mean(x) for x in kitsune]

    # Calculate the standard deviation
    ztrke2_stds = [np.std(x) for x in ztrke2]
    kitsune_stds =  [np.std(x) for x in kitsune]

    # Define labels, positions, bar heights and error bar heights
    labels = ['Accuracy', 'Precision', 'Recall','F1']
    x_pos = np.arange(len(labels))
    data_zt = ztrke2_means
    data_kt = kitsune_means
    error_zt = ztrke2_stds
    error_kit = kitsune_stds
    #   A P R F 
    # Mean
    # Std
    # Arc (1-ztrke2)
    # dp = list()
    # for i,_ in enumerate(data_zt): 
    #     dp.append([data_zt[i],error_zt[i],'ZT_RKE2',labels[i]])
    # for i,_ in enumerate(data_kt): 
    #     dp.append([data_kt[i],error_kit[i],'KITSUNE',labels[i]])

    # df = pd.DataFrame(dp)
    # df.columns = ['MEAN','STD','MODEL','METRIC']
    # kit_dat = df[df['MODEL'] == 'KITSUNE']
    # zt_dat = df[df['MODEL'] == 'ZT_RKE2']
    # print("DATA:\n",df)
    # print(kit_dat)
    # print(zt_dat)
    # # print(data_zt,error_zt)
    # fig, ax = plt.subplots()
    # ax.bar(df,
    #     x='MEAN',
    #     yerr='STD',
    #     color='MODEL',
    #     height=1,
    #     align='center',
    #     alpha=0.5,
    #     ecolor='black',
    #     capsize=10
    #     )

    # Add some text for labels, title and custom x-axis tick labels, etc.
    # Build the plot
    fig, ax = plt.subplots()
    zt_bar = ax.bar(x_pos + 0.25, ztrke2_means,
        yerr=ztrke2_stds,
        # align='center',
        alpha=0.5,
        width=0.25,
        label="ZT_RKE2",
        ecolor='black',
        capsize=10)
    # ax.bar_label(zt_bar, padding=3)
    kt_bar = ax.bar(x_pos + 0.5, kitsune_means,
        yerr=kitsune_stds,
        # align='center',
        alpha=0.5,
        width=0.25,
        label="KITSUNE",
        ecolor='blue',
        capsize=10)
    # ax.bar_label(kt_bar,padding=3)
    ax.set_ylabel('Proportion')
    ax.legend(loc='upper left',ncols=2)
    ax.set_ybound(0,1.1)
    ax.set_xticks(x_pos + 0.375)
    ax.set_xticklabels(labels)
    ax.set_title('Metric Comparison - 15 Trials')
    ax.yaxis.grid(True)


    # Save the figure and show
    plt.tight_layout()
    plt.savefig('aggregated_15_trials.png')
    plt.show()

