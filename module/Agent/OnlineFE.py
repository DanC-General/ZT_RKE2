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
import numpy as np
import os.path
import subprocess
import Packet
from collections import deque
import time

#Extracts Kitsune features from given pcap file one packet at a time using "get_next_vector()"
class OnlineFE:
    def __init__(self,qlen = 100):
        self.packets = deque(maxlen=qlen) 
        self.curPacketIndx = 0

        ### Prep Feature extractor (AfterImage) ###
        maxHost = 100000000000
        maxSess = 100000000000
        self.nstat = ns.netStat(np.nan, maxHost, maxSess)
        # Need to get the first packet to initialise the nstat values
        # self.get_next_vector()

# PACKET 
    def get_next_vector(self):
        while len(self.packets) == 0: 
            # Check error / null return
            # return []
            # Maybe just wait until a packet is received or for a timeout
            time.sleep(0.5)
        # Check remove
        packet = self.packets.pop()
        self.curPacketIndx = self.curPacketIndx + 1
        print(0, type(0), packet.smac, type(packet.smac),
               packet.dmac, type(packet.dmac), packet.sip, type(packet.sip),
               packet.sport, type(packet.sport), packet.dip, type(packet.dip), 
               packet.dport, type(packet.dport), type(packet.size),
               type(packet.ts))
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
        print(self.nstat.getNetStatHeaders())
        return len(self.nstat.getNetStatHeaders())
