#clear-caches
echo "=== 30 ===" >> results.txt
../src/central-manager & 
cental_pid=$!
sleep 10
numactl -N0 -m0 -- ./gups-pebs 16 1000000000 39 8 30 0 ./gups_per_sec.txt >> results.txt
kill -9 ${cental_pid}
#clear-caches
echo "=== 31 ===" >> results.txt
numactl -N0 -m0 -- ./gups-pebs 16 1000000000 39 8 31 0 ./gups_per_sec.txt >> results.txt
#clear-caches
echo "=== 32 ===" >> results.txt
numactl -N0 -m0 -- ./gups-pebs 16 1000000000 39 8 32 0 ./gups_per_sec.txt >> results.txt
#clear-caches
echo "=== 33 ===" >> results.txt
numactl -N0 -m0 -- ./gups-pebs 16 1000000000 39 8 33 0 ./gups_per_sec.txt >> results.txt
#clear-caches
echo "=== 34 ===" >> results.txt
numactl -N0 -m0 -- ./gups-pebs 16 1000000000 39 8 34 0 ./gups_per_sec.txt >> results.txt
#clear-caches
echo "=== 35 ===" >> results.txt
numactl -N0 -m0 -- ./gups-pebs 16 1000000000 39 8 35 0 ./gups_per_sec.txt >> results.txt
#clear-caches
echo "=== 36 ===" >> results.txt
numactl -N0 -m0 -- ./gups-pebs 16 1000000000 39 8 36 0 ./gups_per_sec.txt >> results.txt
#clear-caches
echo "=== 37 ===" >> results.txt
numactl -N0 -m0 -- ./gups-pebs 16 1000000000 39 8 37 0 ./gups_per_sec.txt >> results.txt
#clear-caches
echo "=== 38 ===" >> results.txt
numactl -N0 -m0 -- ./gups-pebs 16 1000000000 39 8 38 0 ./gups_per_sec.txt >> results.txt
