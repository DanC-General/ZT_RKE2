#Check if cython code has been compiled
import os
import subprocess

use_extrapolation=False #experimental correlation code
if use_extrapolation:
    print("Importing AfterImage Cython Library")
    if not os.path.isfile("AfterImage.c"): #has not yet been compiled, so try to do so...
        cmd = "python setup.py build_ext --inplace"
        subprocess.call(cmd,shell=True)
#Import dependencies
import netStat as ns
import csv
import numpy as np
print("Importing Scapy Library")
from scapy.all import *
import os.path
import platform
import subprocess
from ..rules import *
import time

#Extracts Kitsune features from given pcap file one packet at a time using "get_next_vector()"
# If wireshark is installed (tshark) it is used to parse (it's faster), otherwise, scapy is used (much slower).
# If wireshark is used then a tsv file (parsed version of the pcap) will be made -which you can use as your input next time
class OnlineFE:
    def __init__(self,qlen = 100):
        self.packets = deque(maxlen=qlen) 
        self.curPacketIndx = 0

        ### Prep Feature extractor (AfterImage) ###
        maxHost = 100000000000
        maxSess = 100000000000
        self.nstat = ns.netStat(np.nan, maxHost, maxSess)

# PACKET 
    def get_next_vector(self):
        while len(self.packets == 0): 
            # Check error / null return
            # return []
            # Maybe just wait until a packet is received or for a timeout
            time.sleep(1.5)
        # Check remove
        packet = self.packets.pop()
        self.curPacketIndx = self.curPacketIndx + 1

#  Just splices out and retrieves these details from packets 
        ### Extract Features
        try:
            return self.nstat.updateGetStats(0, packet.smac, packet.dmac, packet.sip, packet.sport, packet.dip, packet.dport,
                                                 packet.size,
                                                 packet.ts)
        except Exception as e:
            print(e)
            return []

    def get_num_features(self):
        return len(self.nstat.getNetStatHeaders())
