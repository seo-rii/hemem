#!/bin/sh

for i in `seq 31 38`; do
  workset=$((i + 1))
  warmset=$((i))
  echo "=== $warmset ==="
  echo "=== $warmset ===" >> warmset-results.txt
  numactl -N 1 -m 1,3 -- ./gups-warmset-znuma 16 1000000000 $workset 8 $warmset 0 /tmp/warmsweep.$i.txt >> warmset-results.txt
done

