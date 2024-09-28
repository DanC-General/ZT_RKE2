from argparse import ArgumentParser
import statistics
import numpy as np
import matplotlib.pyplot as plt
parser = ArgumentParser()
parser.add_argument("file",help="Path of file to write to")
args = parser.parse_args()
kitsune = [list() for x in range(0,4)]
ztrke2 = [list() for x in range(0,4)]
cur_ztrke2 = True
i = 0
kit_count = 0
zt_count = 0
with open(args.file,'r') as f: 
    for line in f: 
        line = line.strip()
        print("COUNTS",zt_count,kit_count)
        if line.strip().startswith("ACC"):
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
    print(data_zt,error_zt)
    fig, ax = plt.subplots()
    ax.bar(x_pos, data_zt,
        yerr=error_zt,
        align='center',
        alpha=0.5,
        ecolor='black',
        capsize=10)

    ax.set_ylabel("Proportion")
    ax.set_xticks(x_pos)
    ax.set_xticklabels(labels)
    ax.set_title('Metric Comparisons - 15 trials')
    ax.yaxis.grid(True)


    # Save the figure and show
    plt.tight_layout()
    plt.savefig('bar_plot_with_error_bars.png')
    plt.show()
