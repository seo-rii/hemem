while :
do
    perf stat -e mem_load_l3_miss_retired.local_dram,mem_load_retired.local_pmm &
    perf_pid=$!;
    sleep 1;
    kill -9 ${perf_pid};
done