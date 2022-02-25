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
Noise_Device_MAC = 'xx:xx:xx:xx:xx:xx' # MAC address of the device in trace file

noise = rdpcap(Noise_Trace + ".pcap")
    
t_start = noise[0].time    
t_window = 60

noise_from_Device = {}
Seq_Device_index = []

# This loop creates segments from the pacap file for noise injection
i = 0
while True:
    # Stop if reaching the end of the pcap file    
    if (t_start >= noise[-1].time):
        break
            
    # addr2 is the sender    
    N_Device = (pkt for pkt in noise if ((pkt.addr2 == Noise_Device_MAC) and (pkt.time >= t_start and pkt.time <= t_start + t_window)))
    
    noise_from_Device [i] = {}
    noise_from_Device [i]['Time'] = []
    noise_from_Device [i]['Size'] = []
    
    for pkt in N_Device:
        noise_from_Device [i]['Time'].append(pkt.time)
        noise_from_Device [i]['Size'].append(len(pkt))
              
    # Add segments that have more than one packet.
    if len(noise_from_Device [i]['Size']) > 1:
        Seq_Device_index.append(i)
    
    # increment to the next time window
    i += 1
    t_start = t_start + t_window

############################
#  Device-side Injection
############################

while True:
    
    # Choose randomly a segment
    S = random.choice(Seq_Device_index)
    Volume = len(noise_from_Device [S]['Size'])
        
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
            DummyPkt = IP(src=Device_IP, dst=AP_IP, proto=17, flags= 'evil')
            DummyPkt /= UDP(dport=0)
            DummyPkt /= Raw('X'*(Size-42))
            time.sleep(random.uniform(0.00, 0.09))
            send(DummyPkt)
                
        r = random.uniform(0.00, 0.09)    
            
        interval = (noise_from_Device [S]['Time'][i] - noise_from_Device [S]['Time'][i-1]) + r
        Size = noise_from_Device [S]['Size'][i]
        
        DummyPkt = IP(src=Device_IP, dst=AP_IP, proto=17, flags= 'evil')
        DummyPkt /= UDP(dport=0)
        DummyPkt /= Raw('X'*(Size-42))
        
        time.sleep(interval)
        send(DummyPkt)

