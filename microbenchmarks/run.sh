#sync && echo 3 >| /proc/sys/vm/drop_caches
#clear-caches
echo "=== 30 ===" >> results.txt
echo "=== 30 ===" >> error.txt
numactl -N0 -m0 -- ./gups-pebs 16 1000000000 39 8 30 >> results.txt 2>>error.txt
#clear-caches
echo "=== 31 ===" >> results.txt
echo "=== 31 ===" >> error.txt
numactl -N0 -m0 -- ./gups-pebs 16 1000000000 39 8 31 >> results.txt 2>>error.txt
#clear-caches
echo "=== 32 ===" >> results.txt
echo "=== 32 ===" >> error.txt
numactl -N0 -m0 -- ./gups-pebs 16 1000000000 39 8 32 >> results.txt 2>>error.txt
#clear-caches
echo "=== 33 ===" >> results.txt
echo "=== 33 ===" >> error.txt
numactl -N0 -m0 -- ./gups-pebs 16 1000000000 39 8 33 >> results.txt 2>>error.txt
#clear-cachese
echo "=== 34 ===" >> results.txt
echo "=== 34 ===" >> error.txt
numactl -N0 -m0 -- ./gups-pebs 16 1000000000 39 8 34 >> results.txt 2>>error.txt
#clear-caches
echo "=== 35 ===" >> results.txt
echo "=== 35 ===" >> error.txt
numactl -N0 -m0 -- ./gups-pebs 16 1000000000 39 8 35 >> results.txt 2>>error.txt
#clear-caches
echo "=== 36 ===" >> results.txt
echo "=== 36 ===" >> error.txt
numactl -N0 -m0 -- ./gups-pebs 16 1000000000 39 8 36 >> results.txt 2>>error.txt
#clear-caches
echo "=== 37 ===" >> results.txt
echo "=== 37 ===" >> error.txt
numactl -N0 -m0 -- ./gups-pebs 16 1000000000 39 8 37 >> results.txt 2>>error.txt
#clear-caches
echo "=== 38 ===" >> results.txt
echo "=== 38 ===" >> error.txt
numactl -N0 -m0 -- ./gups-pebs 16 1000000000 39 8 38 >> results.txt 2>>error.txt
