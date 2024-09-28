from argparse import ArgumentParser

if __name__ == "__main__": 
    parser = ArgumentParser()
    # parser.add_argument("file", help="Path of file to anlayse")
    parser.add_argument("file",help="Path of file to analyse")
    args = parser.parse_args()
    avg_times = list()
    metric_at_times = list()
    with open(args.file,'r') as f:
        for line in f: 
            if line.startswith("Time"):
                # print(line,line.split(" "))
                det = line.split(" ") 
                if len(det) == 2: 
                    proc_time = float(det[1]) 
                else:
                    proc_time = float(det[2]) 
                avg_times.append(proc_time)
        
    print(sum(avg_times)/float(len(avg_times)))
