#!/usr/bin/env python
# coding: utf-8

# In[ ]:


from scapy.all import *
import time
import os
import numpy as np
from numpy import random

# Input IP addresses of AP and client device
AP_IP = '000.000.000.1'
Device_IP = '0000.000.000.11' # Suppose this is the IP of device x, then the pacap below should belong to device y

# Identifiers for the trace file
Noise_Trace = 'xxxx' # Pcap File Name
Noise_AP_MAC = 'xx:xx:xx:xx:xx:xx' # MAC address of the AP in trace file

noise = rdpcap(Noise_Trace + ".pcap")
    
t_start = noise[0].time    
t_window = 60

noise_from_AP = {}
Seq_AP_index = []

# This loop creates segments from the pacap file for noise injection
i = 0
while True:
    
    # Stop if reaching the end of the pcap file
    if (t_start >= noise[-1].time):
        break
            
    # addr2 is the sender    
    N_AP = (pkt for pkt in noise if ((pkt.addr2 == Noise_AP_MAC) and (pkt.time >= t_start and pkt.time <= t_start + t_window)))
    
    noise_from_AP [i] = {}
    noise_from_AP [i]['Time'] = []
    noise_from_AP [i]['Size'] = []
    
    for pkt in N_AP:
        noise_from_AP [i]['Time'].append(pkt.time)
        noise_from_AP [i]['Size'].append(len(pkt))
              
    # Add segments that have more than one packet.
    if len(noise_from_AP [i]['Size']) > 1:
        Seq_AP_index.append(i)
    
    # increment to the next time window
    i += 1
    t_start = t_start + t_window


############################
#  AP-side Injection
############################

while True:
        
    # Choose randomly a segment
    S = random.choice(Seq_AP_index)
    Volume = len(noise_from_AP [S]['Size'])
        
    drop_Prob = random.uniform(0.0, 0.05)
    replace_Prob = random.uniform(0.0, 0.05)
        
    drop_List = random.choice([1, 0], p=[drop_Prob, 1 - drop_Prob], size=(Volume))
    replace_List = random.choice([1, 0], p=[replace_Prob, 1 - replace_Prob], size=(Volume))
        
    for i in range(1, Volume):

        if drop_List[i] == 1:
            continue
                
        if replace_List[i] == 1:
            Size = random.randint(28, 1554)
            
            # We use RFC3514 ("The Evil Bit") to set the reserved bit flage to 1 to disntighish dummy packets.
            # The "Evil bit" is unused in practice and was released on April Fools’ Day of 2003.
            # Reference: https://en.wikipedia.org/wiki/Evil_bit
            DummyPkt = IP(src=AP_IP, dst=Device_IP, proto=17, flags= 'evil')
            DummyPkt /= UDP(dport=0)
            DummyPkt /= Raw('X'*(Size-42))
            time.sleep(random.uniform(0.00, 0.09))
            send(DummyPkt)

        r = random.uniform(0.00, 0.09)    
            
        interval = (noise_from_AP [S]['Time'][i] - noise_from_AP [S]['Time'][i-1]) + r
        Size = noise_from_AP [S]['Size'][i]
        
        DummyPkt = IP(src=AP_IP, dst=Device_IP, proto=17, flags= 'evil')
        DummyPkt /= UDP(dport=0)
        DummyPkt /= Raw('X'*(Size-42))
        
        time.sleep(interval)
        send(DummyPkt)

