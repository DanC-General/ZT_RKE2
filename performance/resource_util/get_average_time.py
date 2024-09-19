if __name__ == "__main__": 
    avg_times = list()
    metric_at_times = list()
    with open("./kit_proc.log",'r') as f:
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
