import matplotlib.pyplot as plt
import re
import sys
import numpy as np

MAX_LATENCY = 200

if len(sys.argv) >= 2:
    BG_PREFIXES=sys.argv[1].split(",")
else:
    BG_PREFIXES=["bg_dram_base", "bg_hemem", "bg_mini_hemem"]
print(BG_PREFIXES)

if len(sys.argv) >= 3:
    BG_APPS=sys.argv[2].split(",")
else:
    BG_APPS=["alone", "gups", "gapbs"]
print(BG_APPS)

if len(sys.argv) >= 4:
    RES=sys.argv[3]
else:
    RES="./results"
print(RES)


tput_pattern = re.compile(r"TP: total=[0-9]+\.[0-9]+ mops")

for file_pref in BG_PREFIXES:
    throughput = dict()
    for app in BG_APPS:
        infile = open(RES + "/" + file_pref + "_" + app + "_flexkv.txt", encoding='utf8').read()
        # Throughput of app
        throughput[app] = []
        matches = tput_pattern.findall(infile)
        for match in matches:
            match = re.compile(r"[0-9]+\.[0-9]+").search(match)
            if match:
                throughput[app].append(np.float64(match.group(0)))

    for i in throughput.keys():
        if(len(throughput[i]) > 1):
            plt.plot(np.arange(0, len(throughput[i][1:])), throughput[i][1:], label=i)
    plt.legend()
    plt.savefig(file_pref + "_timeline.png", bbox_inches='tight',pad_inches = 0)
    plt.clf()

                

