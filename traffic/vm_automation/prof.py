import os
rd_cmds = ["cat","less","head","tail","man","file"]
wr_cmds = ["cp","mv","unzip"," >",">>","tee","mkdir","touch"]
ed_cmds = ["vim","sed", "tr","nano","awk","vi","rm","rmdir","chmod"]
srch_mv_cmds = ["cd", "ls","la","l","which", "whereis", "grep", "find","dirname","pwd"]
# Other executable commands
["clear","ping google.com -c 1","ip a","ps", "ss", "jobs","apt update"]
cur = [0,0,0,0,0]
firsts = [0,0,0,0,0,0]
def check_list(text,lst):
    # if any(cmd in text for cmd in lst): 
    for cmd in lst:
        if cmd + " " in text or cmd + "\n" in text:
            # print(cmd)
            return 1
    return 0  
def make_weights(path="/home/dc/History"):
    global cur
    total_counts = [0,0,0,0,0,0]
    unique_cmds = set()
    per_category_counts = [[0]*5 for x in range(5)]
    per_category_counts[0][0] = 1
    print(per_category_counts)
    # exit()
    for root, dirs,files in os.walk(path):
        for file in files:
            is_first = False
            if ".prof" in file: 
                # read,write,edit,search/move,execute,total
                cur_counts = [0,0,0,0,0,0]
                # print("found ", file)
                full = os.path.join(root,file)
                print(full)
                with open(full, "r") as f: 
                    for line in f: 
                        # print("Start: " ,line)
                        previous = cur.copy()
                        cur = [0,0,0,0,0]
                        matches = 0
                        # print("i prev",previous)
                        # print("i cur",cur)
                        for i,cmds in enumerate([rd_cmds,wr_cmds,ed_cmds,srch_mv_cmds]): 
                            # print(i, check_list(line,cmds))
                            cur_counts[i] += check_list(line,cmds)
                            if (check_list(line,cmds) == 1): 
                                cur[i] = 1
                                matches +=1
                                # print(i, line)
                                for xi,x in enumerate(previous): 
                                    if previous[xi] == 1: 
                                        per_category_counts[xi][i] += 1
                                if is_first: 
                                    firsts[i] += 1
                                    firsts[-1] += 1
                        if not matches: 
                            # print("||" , line.split(" ")[0])
                            cur[-1] = 1
                            unique_cmds.add(line.split(" ")[0])
                            for xi,x in enumerate(previous): 
                                if previous[xi] == 1: 
                                    per_category_counts[xi][-1] += 1
                            if is_first: 
                                firsts[-1] += 1
                                firsts[-2] += 1
                        # print("e prev",previous)
                        # print("e cur",cur)
                        cur_counts[-1] +=1 
                        if "exit" in line: 
                            is_first = True
                        else: 
                            is_first = False
                cur_counts[-2] = cur_counts[-1] - sum(cur_counts[0:4])
                print(cur_counts)
                total_counts = list(map(lambda c,n: c+n,cur_counts,total_counts))
                # print(unique_cmds)
                # print(total_counts)
                # break
        break

    weights = list(map(lambda x: int(x)/int(total_counts[-1]) * 100,total_counts[:-1]))
    print(weights)
    print(sum(weights))
    print(per_category_counts)
    print("Overall distributions",calc_weights(total_counts[:-1]))
    print("Per category distributions",list(map(lambda x:calc_weights(x),per_category_counts)))
    print("First command distributions ", calc_weights(firsts[:-1]))
    return weights

def calc_weights(arr): 
    # total = sum(arr)
    return list(map(lambda x: x/sum(arr) * 100,arr))
make_weights()