import os
rd_cmds = ["cat","less","head","tail","man","file"]
wr_cmds = ["cp","mv","unzip"," >",">>","tee","mkdir","touch"]
ed_cmds = ["vim","sed", "tr","nano","awk","vi","rm","rmdir","chmod"]
srch_mv_cmds = ["cd", "ls","la","which", "whereis", "grep", "find","dirname","pwd"]
# Other executable commands
["clear","ping google.com -c 1","ip a","ps", "ss", "jobs","apt update"]
total_counts = [0,0,0,0,0,0]
unique_cmds = set()
def check_list(str,lst):
    if any(cmd in str for cmd in lst): 
        return 1
    return 0  
def make_weights(path="/home/dc/History"):
    for root, dirs,files in os.walk(path):
        for file in files:
            if ".prof" in file: 
                # read,write,edit,execute,total
                cur_counts = [0,0,0,0,0,0]
                print("found ", file)
                full = os.path.join(root,file)
                print(full)
                with open(full, "r") as f: 
                    for line in f: 
                        # print("l" ,line)
                        matches = 0
                        for i,cmds in enumerate([rd_cmds,wr_cmds,ed_cmds,srch_mv_cmds]): 
                            # print(i, check_list(line,cmds))
                            cur_counts[i] += check_list(line,cmds)
                            if (check_list(line,cmds) == 1): 
                                matches +=1
                                print(i, line)
                        if not matches: 
                            print("||" , line.split(" ")[0])
                            unique_cmds.add(line.split(" ")[0])
                        cur_counts[-1] +=1 
                cur_counts[-2] = cur_counts[-1] - sum(cur_counts[0:4])
                print(cur_counts)
                total_counts = list(map(lambda c,n: c+n,cur_counts,total_counts))
                print(unique_cmds)
                print(total_counts)
                # break
        break

    weights = list(map(lambda x: int(x)/int(total_counts[-1]) * 100,total_counts[:-1]))
    print(weights)
    print(sum(weights))