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


hist_pattern = re.compile(r"Hist\[[0-9]+\]=[0-9]+")
tput_pattern = re.compile(r"Final throughput = [0-9]+\.[0-9]+ mops")

for file_pref in BG_PREFIXES:
    latencies = dict()
    throughput = dict()
    #print(file_pref, "\nApp\tThroughput\tAvg latency\t95%% latency\t99%% latency")
    for app in BG_APPS:
        infile = open(RES + "/" + file_pref + "_" + app + "_flexkv.txt", encoding='utf8').read()
        # Latency histogram for app
        latencies[app] = np.zeros(MAX_LATENCY, dtype=np.int64)
        matches = hist_pattern.findall(infile)
        for hist_elem in matches:
            hist_elem = re.compile(r"[0-9]+").findall(hist_elem)
            index = int(hist_elem[0])
            value = int(hist_elem[1])
            if(index >= MAX_LATENCY):
                latencies[app][MAX_LATENCY - 1] += value
            else:
                latencies[app][index] += value
        # Throughput of app
        throughput[app] = ""
        match = tput_pattern.search(infile)
        if match:
            match = re.compile(r"[0-9]+\.[0-9]+").search(match.group(0))
            if match:
                throughput[app] = match.group(0)
    
    outfile = open(file_pref + "_summary.out", "w", encoding='utf8')
    outfile.write(file_pref + "\n")
    # Output throughputs
    outfile.write("Throughput\t")
    for app in BG_APPS:
        outfile.write(app + "\t")
    outfile.write("\n\t")
    for app in BG_APPS:
        outfile.write(throughput[app] + "\t")
    outfile.write("\n")

    # Output histogram
    cdf = dict()
    total_sum = dict()
    outfile.write("Latency percentiles\t")
    for app in BG_APPS:
        cdf[app] = 0
        total_sum[app] = np.sum(latencies[app])
        outfile.write(app + "\t")
    outfile.write("\n")
    for i in range(MAX_LATENCY):
        outfile.write(str(i) + "\t")
        for app in BG_APPS:
            cdf[app] += latencies[app][i]
            outfile.write(str(cdf[app] / total_sum[app]) + "\t")
        outfile.write("\n")
    outfile.close()


                

