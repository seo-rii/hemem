#!/bin/bash
PROC=$1

while kill -0 $PROC 2> /dev/null; do
    # Get node-wise memory usage
    MEM_USAGE=($(numastat -p $PROC | grep ^Total | grep -Eo "[0-9]+\.[0-9]+"));
    # Now divide this into DRAM usage and NVM usage.
    # Assumption: first 2 nodes are DRAM, next 2 nodes are NVM
    DRAM_USAGE=$(echo "${MEM_USAGE[0]} + ${MEM_USAGE[1]} / 1024.0" | bc);
    NVM_USAGE=$(echo "${MEM_USAGE[2]} + ${MEM_USAGE[3]} / 1024.0" | bc);
    printf "%.0f GB DRAM, %.0f GB NVM\n" ${DRAM_USAGE} ${NVM_USAGE};
    sleep 1
done
