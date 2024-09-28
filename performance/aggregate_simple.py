from argparse import ArgumentParser
import statistics
parser = ArgumentParser()
parser.add_argument("file",help="Path of file to write to")
args = parser.parse_args()
kitsune = [list() for x in range(0,4)]
ztrke2 = [list() for x in range(0,4)]
cur_ztrke2 = True
with open(args.file,'r') as f: 
    for line in f: 
        line = line.strip()
        if line.strip().startswith("ACC"):
            det = line.split(',')
            print("Detail ",det)
            for i,item in enumerate(det):
                values = [x.strip() for x in item.split(':')]
                if cur_ztrke2:
                    ztrke2[i].append(float(values[1]))
                else: 
                    kitsune[i].append(float(values[1]))
                print(i,values)
            cur_ztrke2 = not cur_ztrke2
    print("Kitsune")
    print([statistics.mean(x) for x in kitsune])
    print("ZT_RKE2")
    print([statistics.mean(x) for x in ztrke2])