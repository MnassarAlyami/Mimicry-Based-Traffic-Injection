# Mimicry-Based-Traffic-Injection

A Python script implements the mimicry-based injection algorithm from the paper "MAC-layer Traffic Shaping Defense Against WiFi Device Fingerprinting Attacks."

Environment: Python 3.8.10

In AP_Side_Injection.py and Device_Side_Injection.py, the script injects the dummy packets at the Access Point (AP) and device, respectively. Before running the code, make sure to input the corresponding addresses according to the network settings.
Example:
AP_IP = '192.175.826.1'
Device_IP = '192.175.826.11'

The code requires a pcap file to mimic a device. So, provide the needed identifiers from that trace for processing.

Example:
Noise_Trace = 'My Camera'  # File name.
Noise_AP_MAC = 'ab:74:f5:27:05:9f'  # AP MAC address from the trace file.
Noise_Device_MAC = '7b:82:49:ff:78:a8' # Device MAC address from the trace file.
