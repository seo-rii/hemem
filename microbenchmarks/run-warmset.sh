#!/bin/sh
debugfile=/tmp/debug.txt
rm -f $debugfile

./run-perf.sh >/dev/null 2>&1 &
run_perf_pid=$!

for i in `seq 31 38`; do
  nice -20 numactl -C0,1,2,3 -m0 -- ./../src/central-manager >$debugfile 2>&1 &
  central_pid=$!
  sleep 5
  workset=$((i + 1))
  warmset=$((i))
  echo "=== $warmset ==="
  echo "=== $warmset ===" >> warmset-results.txt
  numactl -N0 -m0 -- env LD_PRELOAD=/home/amanda/hemem/src/libhemem.so ./gups-warmset 16 1000000000 $workset 8 $warmset 0 /tmp/warmsweep.$i.txt >> warmset-results.txt
  kill -9 ${central_pid}
  sleep 5
done

kill -9 ${run_perf_pid}
pkill perf
