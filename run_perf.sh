#!/bin/sh

while :
do
    /home/midhul/colloid/linux-6.3/tools/perf/perf stat -e mem_load_l3_miss_retired.local_dram,mem_load_l3_miss_retired.remote_dram -C3,7,11,15,19,23,27,31 &
    perf_pid=$!;
    sleep 1;
    kill -9 ${perf_pid};
done

