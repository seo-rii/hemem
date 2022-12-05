#!/bin/sh

for i in `seq 30 38`; do
  echo "=== $i ===" >> results.txt
  nice -20 numactl -C0,1,2,3,4,5,6,7,23 -m0 -- ./../src/central-manager &
  central_pid=$!
  sleep 5
  numactl -N0 -m0 -- env LD_PRELOAD=/home/amanda/hemem/src/libhemem.so ./gups-pebs 16 1000000000 39 8 $i 0 hotsweep.$1.txt >> results.txt
  kill -9 ${central_pid}
  sleep 5
done
