from analysis_cls import Analyser,Attacks,Attack,Request,timestr_to_obj
import datetime
import os
import statistics

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

def get_groups_from_analyser(results,atks):
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
    # print("A_G:",all_groups)
    # print("C_G",groups)
    seen = []
    unseen = []
    for grp in all_groups:
        if grp[8] is None:
            continue
        if grp[8] not in seen:
            # print(grp[8],datetime.datetime.fromtimestamp(grp[0]).time(),grp[7])
            seen.append(grp[8])
        else:
            # print("Duplicate",grp[8],grp[1],grp[7])
            # print(start_time,"list:")
            for i in atks.get_60s_ts(float(grp[1]),float(grp[2]),grp[7]):
                # print("        ",i)
                # print("NEW_ID",i.id)
                if i.id not in seen:
                    # print("ADDED UNSEEN",i.id)
                    # print(grp[8],datetime.datetime.fromtimestamp(grp[0]).time(),grp[7])
                    seen.append(i.id)
    for atk in atks.all: 
        if atk.id not in seen and atk.id is not None:
            # print("Missing",atk)
            if atk.id not in unseen: 
                unseen.append(atk.id)


    total_atks = len(atks.all)
    # print("ATK LEN",len(atks.all))
    count = results.total_count
    total_pos = fal_pos + true_pos
    pos_p = total_pos / count
    neg_p = 1 - pos_p
    tp_p = (true_pos / total_pos) * pos_p
    fp_p = (fal_pos / total_pos) * pos_p
    fn_p = (len(unseen)/total_atks) * neg_p
    tn_p = (1 - tp_p - fp_p - fn_p) * neg_p
    print("PARSED ", count, "packets")
    # print("LISTS",host_list)
    # print("IDS",len(seen),seen)
    print("POSTIIVE COUNTS", count, "FP",fal_pos,"TP",true_pos)
    print("NEGATIVE COUNTS",total_atks,"SEEN",len(seen),"UNSEEN",len(unseen))
    print("TRUE POSITIVES",tp_p,"FALSE POSITIVES",fp_p,"TRUE NEGATIVES",tn_p,"FALSE NEGATIVES",fn_p)
    metrics = [tp_p,fp_p,tn_p,fn_p]
    return all_groups, metrics

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