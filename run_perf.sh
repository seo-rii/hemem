#!/bin/sh

while :
do
    /home/midhul/linux-6.3/tools/perf/perf stat -e mem_load_l3_miss_retired.local_dram,mem_load_l3_miss_retired.remote_dram -C1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,45,47,49,51,53,55,57,59,61,63 &
    perf_pid=$!;
    sleep 1;
    kill -9 ${perf_pid};
done

