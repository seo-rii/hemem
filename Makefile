.PHONY: all Hoard HeMem GUPS FlexKVS GAPBS\
	run_flexkvs run_gups run_gapbs run_bt \
	run_bg_dram_base run_bg_hw_tier run_bg_sw_tier \
	 

default: all

# <--------------------------- SETUP NVM COMMANDS --------------------------->
# NOTE: Reboot is required along with setting appropriate BIOS options

setup_mm:
	sudo ndctl destroy-namespace all --force
	sudo ipmctl create -goal MemoryMode=100

setup_hemem_numa_preboot:
	sudo ipmctl create -goal PersistentMemoryType=AppDirect

setup_numa_postboot:
	sudo ndctl destroy-namespace all --force
	numactl -H
	sudo ndctl create-namespace --region=1 --mode=devdax --map=mem -c
	sudo ndctl create-namespace --region=2 --mode=devdax --map=mem -c
	daxctl list
	sudo daxctl reconfigure-device dax1.0 --mode=system-ram -f
	sudo daxctl reconfigure-device dax2.0 --mode=system-ram -f
	numactl -H
	echo "1" > /proc/sys/kernel/numa_balancing

setup_hemem_postboot:
	sudo ndctl create-namespace -f -e namespace0.0 --mode=devdax --align 2M
	sudo ndctl create-namespace --region=1 --mode=devdax
	ndctl list
	echo "0" > /proc/sys/kernel/numa_balancing

# <----------------------------- BUILD COMMANDS -----------------------------> 

RES ?= ./results

${RES}:
	mkdir -p ${RES};

# Command to make sure all apps and hemem are freshly compiled
all: ${RES} Hoard HeMem GUPS FlexKVS GAPBS

Hoard:
	cd Hoard/src; $(MAKE)

HeMem:
	cd src; $(MAKE);

GUPS:
	cd microbenchmarks; $(MAKE);

FlexKVS:
	cd apps/flexkvs; $(MAKE);

GAPBS:
	cd apps/gapbs; $(MAKE)

./Hoard/src/libhoard.so: 
	$(MAKE) Hoard

./src/libhemem.so: ./Hoard/src/libhoard.so
	$(MAKE) HeMem

./src/central-manager: ./Hoard/src/libhoard.so	
	$(MAKE) HeMem

./microbenchmarks/gups:
	$(MAKE) GUPS;

./microbenchmarks/gups-pebs:
	$(MAKE) GUPS;

./apps/flexkvs/flexkvs:
	$(MAKE) FlexKVS;

./apps/flexkvs/kvsbench:
	$(MAKE) FlexKVS;

./apps/gapbs/bc:
	$(MAKE) GAPBS;

# <------------------------------ RUN COMMANDS ------------------------------> 

BASE_NODE ?= 0
OTHER_NODE ?= $$(((${BASE_NODE} + 1) % 2))
NUMA_CMD ?= 
NUMA_CMD_CLIENT ?= 
PRELOAD  ?= 

SET_LOW_PRTY = MISS_RATIO=1.0
SET_HIGH_PRTY = MISS_RATIO=0.1

CMD_KILL_ALL := \
	list_descendants () { \
		local children=$$(ps -o pid= --ppid "$$1"); \
		for pid in $${children}; \
		do \
			list_descendants "$${pid}"; \
		done; \
		echo "$${children}"; \
	}; \
	kill $$(list_descendants $$$$)


# Configs for HeMem
APPSIZE    ?= $$((92*1024*1024*1024))
NVMSIZE    ?= $$((248*1024*1024*1024))
DRAMSIZE   ?= $$((96*1024*1024*1024))
NVMOFFSET  ?= 0
DRAMOFFSET ?= 0

# Configs for app runs
FLEXKV_THDS ?= 4
APP_THDS    ?= 8
ifeq (${BASE_NODE}, 1)
MGR_CPUS    ?= 24-31
MGR_CPU_START ?= 24
APP_CPUS    ?= 32-41
APP_CPUS_START ?= 32
FLEXKV_CPUS ?= 42-47
FLEXKV_CPUS_START ?=42
else
MGR_CPUS    ?= 0-3
MGR_CPU_START ?= 0
APP_CPUS    ?= 4-17
APP_CPUS_START ?= 4
FLEXKV_CPUS ?= 18-23
FLEXKV_CPUS_START ?=18
endif

FLEXKV_SIZE ?= $$((32*1024*1024*1024))
GUPS_SIZE   ?= $$((256*1024*1024*1024))
GAPBS_SIZE  ?= 28
BT_SIZE     ?= E

FLEXKV_PRTY ?= ${SET_HIGH_PRTY}
GUPS_PRTY   ?= ${SET_LOW_PRTY}
GAPBS_PRTY  ?= ${SET_LOW_PRTY}
BT_PRTY			?= ${SET_LOW_PRTY}

# Commands needed by HeMem
SETUP_CMD = export LD_LIBRARY_PATH=./src:./Hoard/src:$LD_LIBRARY_PATH; \
	echo 1000000 > /proc/sys/vm/max_map_count;
HEMEM_PRELOAD = env LD_PRELOAD=./src/libhemem.so

RUN_MGR = nice -20 ./src/central-manager > $${file}_mem_usage.txt & \
	CTRL_MGR=$$!; \
	sleep 20;

KILL_MGR = kill $${CTRL_MGR}; sleep 5;

RUN_PERF = ${NUMA_CMD_CLIENT} ./run_perf.sh & PERF_CMD=$$!;

KILL_PERF = kill $${PERF_CMD}; pkill perf; sleep 5;

FLEXKV_NICE ?= nice -20
FLEXKV_S_WAIT   ?= 160	
FLEXKV_WARMUP   ?= 100	
FLEXKV_RUNTIME  ?= 300
FLEXKV_HOT_FRAC ?= 0.25
FLEXKV_HOT_FRAC2 ?= 0.25

MAXMEM_MEASURE ?= 0
WAIT_BG ?= 0
ZNUMA_MEASURE ?= 0
NUMASTAT ?= ${NUMA_CMD_CLIENT} ./scripts/numastat.sh

# TODO: Can we somehow launch client after server is setup
# instead of waiting an arbitrary amount of time and hoping
# that the server is ready in that time?
run_flexkvs: ./apps/flexkvs/flexkvs ./apps/flexkvs/kvsbench
	-./apps/flexkvs/unlink_socks.sh; # Cleanup

	if [ ${WAIT_BG} -gt 0 ]; then \
	  ./${WAIT_SCRIPT}; \
	fi;\
	NVMSIZE=${NVMSIZE} DRAMSIZE=${DRAMSIZE} \
	NVMOFFSET=${NVMOFFSET} DRAMOFFSET=${DRAMOFFSET} \
	${FLEXKV_PRTY} ${FLEXKV_NICE} \
		${PRELOAD} ./apps/flexkvs/flexkvs flexkvs.conf ${FLEXKV_THDS} ${FLEXKV_SIZE} > ${RES}/${PREFIX}_server.txt & \
	FLEXKVS_SERVER=$$!; \
	if [ ${ZNUMA_MEASURE} -gt 0 ]; then \
		perf stat -e faults -I 1000 -p $${FLEXKVS_SERVER} -o ${RES}/${PREFIX}_flexkv_faults.txt &\
		$${FLEXKVS_SERVER} > ${RES}/${PREFIX}_flexkv_mem_usage.txt & \
	fi; \
	./wait-kvs.sh ${RES}/${PREFIX}_server.txt; \
	${FLEXKV_NICE} \
		./apps/flexkvs/kvsbench -t ${FLEXKV_THDS} -T ${FLEXKV_RUNTIME} -w ${FLEXKV_WARMUP} \
		-h ${FLEXKV_HOT_FRAC} 127.0.0.1:11211 -S $$((15*${FLEXKV_SIZE}/16)) > ${RES}/${PREFIX}_flexkv.txt; \
	if [ ${MAXMEM_MEASURE} -gt 0 ]; then \
		cp /tmp/log-$${FLEXKVS_SERVER}.txt ${RES}/${PREFIX}_flexkv_miss_ratio.txt; \
	fi;

run_flexkvs_grow: ./apps/flexkvs/flexkvs ./apps/flexkvs/kvsbench
	-./apps/flexkvs/unlink_socks.sh; # Cleanup

	HEMEM_START_CPU=${MGR_CPU_START} NVMSIZE=${NVMSIZE} DRAMSIZE=${DRAMSIZE} \
	NVMOFFSET=${NVMOFFSET} DRAMOFFSET=${DRAMOFFSET} \
	${FLEXKV_PRTY} ${FLEXKV_NICE} ${NUMA_CMD} --physcpubind=${FLEXKV_CPUS} \
		${PRELOAD} ./apps/flexkvs/flexkvs flexkvs.conf ${FLEXKV_THDS} ${FLEXKV_SIZE} & \
	sleep ${FLEXKV_S_WAIT}; \
	${FLEXKV_NICE} ${NUMA_CMD_CLIENT} \
		./apps/flexkvs/kvsbench -t ${FLEXKV_THDS} -T ${FLEXKV_RUNTIME} -w ${FLEXKV_WARMUP} \
		-h ${FLEXKV_HOT_FRAC} 127.0.0.1:11211 -S $$((15*${FLEXKV_SIZE}/16)) > ${RES}/${PREFIX}_flexkv_1.txt;
	${FLEXKV_NICE} ${NUMA_CMD_CLIENT} \
		./apps/flexkvs/kvsbench -t ${FLEXKV_THDS} -T ${FLEXKV_RUNTIME} -w 0 \
		-h ${FLEXKV_HOT_FRAC2} 127.0.0.1:11211 -S $$((15*${FLEXKV_SIZE}/16)) -l > ${RES}/${PREFIX}_flexkv_2.txt;

GUPS_ITERS ?= 0
run_gups: ./microbenchmarks/gups
	LOG_SIZE=$$(printf "%.0f" $$(echo "l(${APP_SIZE})/l(2)"|bc -l)); \
	HOT_SIZE=$$(printf "%.0f" $$(echo "$${LOG_SIZE} - 2"|bc -l)); \
	${GUPS_PRTY} nice -20 \
		./microbenchmarks/gups ${APP_THDS} ${GUPS_ITERS} ${LOG_SIZE} \
		8 ${HOT_SIZE} 0 ${RES}/${PREFIX}_persecond_gups.txt > ${RES}/${PREFIX}_gups.txt & \
	GUPS_PID=$$!; \
	perf stat -e instructions -I 1000 -p $${GUPS_PID} -o ${RES}/${PREFIX}_gups_ipc.txt &\
	if [ ${ZNUMA_MEASURE} -gt 0 ]; then \
		./scripts/numastat.sh $${GUPS_PID} > ${RES}/$${PREFIX}_gups_mem_usage.txt & \
	fi; \

run_gups_pebs: ./microbenchmarks/gups-pebs
	LOG_SIZE=$$(printf "%.0f" $$(echo "l(${APP_SIZE})/l(2)"|bc -l)); \
	HOT_SIZE=$$(printf "%.0f" $$(echo "$${LOG_SIZE} - 2"|bc -l)); \
	NVMSIZE=${NVMSIZE} DRAMSIZE=${DRAMSIZE} \
	NVMOFFSET=${NVMOFFSET} DRAMOFFSET=${DRAMOFFSET} REQ_DRAM=${REQ_DRAM} \
	${GUPS_PRTY} nice -20 ${NUMA_CMD} --physcpubind=${APP_CPUS} ${PRELOAD} \
		./microbenchmarks/gups-pebs ${APP_THDS} ${GUPS_ITERS} \
		${LOG_SIZE} 8 ${HOT_SIZE} 0 ${RES}/${PREFIX}_persecond_gups.txt > ${RES}/${PREFIX}_gups_pebs.txt & \
	GUPS_PID=$$!;\
	perf stat -e instructions -I 1000 -p $${GUPS_PID} -o ${RES}/${PREFIX}_gups_pebs_ipc.txt &\
	if [ ${ZNUMA_MEASURE} -gt 0 ]; then \
		./scripts/numastat.sh $${GUPS_PID} > ${RES}/$${PREFIX}_gups_pebs_mem_usage.txt & \
	fi;

GAPBS_TRIALS ?= 10
run_gapbs: ./apps/gapbs/bc
	HEMEM_START_CPU=${MGR_CPU_START} NVMSIZE=${NVMSIZE} DRAMSIZE=${DRAMSIZE} NVMOFFSET=${NVMOFFSET} \
	DRAMOFFSET=${DRAMOFFSET} OMP_THREAD_LIMIT=${APP_THDS} \
	${GAPBS_PRTY} nice -20 ${PRELOAD} \
		./apps/gapbs/bc -n ${GAPBS_TRIALS} ${APP_SIZE} > ${RES}/${PREFIX}_gapbs.txt & \
	GAPBS_PID=$$!;\
	perf stat -e instructions -I 1000 -C ${APP_CPUS} -o ${RES}/${PREFIX}_gapbs_ipc.txt &\
	if [ ${ZNUMA_MEASURE} -gt 0 ]; then \
		./scripts/numastat.sh $${GAPBS_PID} > ${RES}/$${PREFIX}_gapbs_mem_usage.txt & \
	fi;

# TODO: Command to run BT
run_bt: 
	HEMEM_START_CPU=${MGR_CPU_START} NVMSIZE=${NVMSIZE} DRAMSIZE=${DRAMSIZE} \
	NVMOFFSET=${NVMOFFSET} DRAMOFFSET=${DRAMOFFSET} OMP_THREAD_LIMIT=${APP_THDS} \
	${BT_PRTY} nice -20 ${NUMA_CMD} --physcpubind=${APP_CPUS} ${PRELOAD} \
		./apps/nas-bt-c-benchmark/NPB-OMP/bin/bt.${BT_SIZE} > ${RES}/${PREFIX}_bt.txt & \
	BT_PID=$$!;\
	perf stat -e instructions -I 1000 -C ${APP_CPUS} -o ${RES}/${PREFIX}_bt_ipc.txt &\
	if [ ${ZNUMA_MEASURE} -gt 0 ]; then \
		./scripts/numastat.sh $${GUPS_PID} > ${RES}/$${PREFIX}_bt_mem_usage.txt & \
	fi;

run_bg_dram_base: all
	PREFIX=bg_dram_base; \
	BASE_NODE=1;\
	APP_SIZE=$$((64*1024*1024*1024)); \
	$(MAKE) run_flexkvs BASE_NODE=$${BASE_NODE} PRELOAD="" \
		FLEXKV_SIZE=$${APP_SIZE} PREFIX=$${PREFIX}_Isolated; \
	wait;\
	pkill flexkvs;\
	$(MAKE) run_flexkvs BASE_NODE=$${BASE_NODE} PRELOAD="" \
		FLEXKV_SIZE=$${APP_SIZE} PREFIX=$${PREFIX}_gups & \
	$(MAKE) run_gups BASE_NODE=$${BASE_NODE} APP_SIZE=$${APP_SIZE} \
		GUPS_ITERS=$$((${GUPS_ITERS} * 2)) PREFIX=$${PREFIX}; \
	wait;\
	pkill flexkvs;\
	$(MAKE) run_gapbs BASE_NODE=$${BASE_NODE} PRELOAD="" APP_SIZE=27 \
		GAPBS_TRIALS=$$((${GAPBS_TRIALS} * 3)) PREFIX=$${PREFIX} & \
	$(MAKE) run_flexkvs BASE_NODE=$${BASE_NODE} PRELOAD="" \
		FLEXKV_SIZE=$${APP_SIZE} PREFIX=$${PREFIX}_gapbs; \
	wait;\
	pkill flexkvs;\
	$(MAKE) run_flexkvs BASE_NODE=$${BASE_NODE} PRELOAD="" \
		FLEXKV_SIZE=$${APP_SIZE} PREFIX=$${PREFIX}_bt & \
	$(MAKE) run_bt BASE_NODE=$${BASE_NODE} PRELOAD=""\
		BT_SIZE=D PREFIX=$${PREFIX}; \
	wait;\
	pkill flexkvs;


run_bg_hw_tier: all
	PREFIX=bg_hw_tier; \
	FLEXKV_SIZE=$$((${APPSIZE})); \
	$(MAKE) run_flexkvs FLEXKV_SIZE=$${FLEXKV_SIZE} PRELOAD="" PREFIX=$${PREFIX}_Isolated; \
	pkill flexkvs;\
	$(MAKE) run_flexkvs FLEXKV_SIZE=$${FLEXKV_SIZE} PRELOAD="" PREFIX=$${PREFIX}_gups & \
	$(MAKE) run_gups APP_SIZE=${GUPS_SIZE} PREFIX=$${PREFIX}; \
	wait; \
	pkill flexkvs;\
	$(MAKE) run_gapbs PRELOAD="" APP_SIZE=${GAPBS_SIZE} GAPBS_TRIALS=$$((${GAPBS_TRIALS} * 3)) PREFIX=$${PREFIX} & \
	$(MAKE) run_flexkvs FLEXKV_SIZE=$${FLEXKV_SIZE} PRELOAD="" PREFIX=$${PREFIX}_gapbs; \
	wait; \
	pkill flexkvs;\
	$(MAKE) run_flexkvs FLEXKV_SIZE=$${FLEXKV_SIZE} PRELOAD="" PREFIX=$${PREFIX}_bt & \
	$(MAKE) run_bt BT_SIZE=${BT_SIZE} PREFIX=$${PREFIX}; \
	wait;\
	pkill flexkvs;

run_znuma_tier: all
	echo "1" > /proc/sys/kernel/numa_balancing;\
	PREFIX=bg_znuma_tier; \
	BASE_NODE=1;\
	FLEXKV_SIZE=$$((${APPSIZE})); \
	$(MAKE) run_flexkvs ZNUMA_MEASURE=1 BASE_NODE=$${BASE_NODE} NUMA_CMD="$${NUMA_CMD}" FLEXKV_SIZE=$${FLEXKV_SIZE} PRELOAD="" PREFIX=$${PREFIX}_Isolated; \
	wait;\
	pkill flexkvs;\
	$(MAKE) run_flexkvs ZNUMA_MEASURE=1 BASE_NODE=$${BASE_NODE} NUMA_CMD="$${NUMA_CMD}" FLEXKV_SIZE=$${FLEXKV_SIZE} PRELOAD="" PREFIX=$${PREFIX}_gups & \
	$(MAKE) run_gups BASE_NODE=$${BASE_NODE} NUMA_CMD="$${NUMA_CMD}" APP_SIZE=${GUPS_SIZE} PRELOAD="" PREFIX=$${PREFIX} & \
	./scripts/numastat.sh $$! > ${RES}/$${PREFIX}_gups_mem_usage.txt; \
	wait; \
	pkill flexkvs;\
	$(MAKE) run_flexkvs ZNUMA_MEASURE=1 BASE_NODE=$${BASE_NODE} NUMA_CMD="$${NUMA_CMD}" FLEXKV_SIZE=$${FLEXKV_SIZE} PRELOAD="" PREFIX=$${PREFIX}_gapbs & \
	$(MAKE) run_gapbs BASE_NODE=$${BASE_NODE} NUMA_CMD="$${NUMA_CMD}" APP_SIZE=${GAPBS_SIZE} PRELOAD="" GAPBS_TRIALS=$$((${GAPBS_TRIALS} * 3)) PREFIX=$${PREFIX} & \
	./scripts/numastat.sh $$! > ${RES}/$${PREFIX}_gapbs_mem_usage.txt; \
	wait; \
	pkill flexkvs;\
	$(MAKE) run_flexkvs ZNUMA_MEASURE=1 BASE_NODE=$${BASE_NODE} NUMA_CMD="$${NUMA_CMD}" FLEXKV_SIZE=$${FLEXKV_SIZE} PRELOAD="" PREFIX=$${PREFIX}_bt & \
	$(MAKE) run_bt BASE_NODE=$${BASE_NODE} NUMA_CMD="$${NUMA_CMD}" BT_SIZE=${BT_SIZE} PPRELOAD="" REFIX=$${PREFIX} & \
	./scripts/numastat.sh $$! > ${RES}/$${PREFIX}_bt_mem_usage.txt; \
	wait;\
	pkill flexkvs;\
	echo "0" > /proc/sys/kernel/numa_balancing;

# FlexKV occupies first half of DRAM/NVM, and other app the other half
run_bg_sw_tier: all
	# HeMem runs
	FLEXKV_SIZE=$$((${APPSIZE})); \
	NVMSIZE=$$((${NVMSIZE}/2)); DRAMSIZE=$$((${DRAMSIZE}/2)); \
	${SETUP_CMD} \
	PREFIX=bg_hemem; \
	file=${RES}/$${PREFIX}_Isolated; \
	${RUN_PERF} \
	$(MAKE) run_flexkvs MAXMEM_MEASURE=1 HEMEM_MGR_START_CPU=0 HEMEM_START_CPU=${FLEXKV_CPUS_START} HEMEM_NUM_CORES=${FLEXKV_THDS} NVMSIZE=$${NVMSIZE} DRAMSIZE=$${DRAMSIZE} PRELOAD="${HEMEM_PRELOAD}" \
		NVMOFFSET=0 DRAMOFFSET=0 FLEXKV_SIZE=$${FLEXKV_SIZE} PREFIX=$${PREFIX}_Isolated; \
	pkill flexkvs;\
	$(MAKE) run_flexkvs MAXMEM_MEASURE=1 WAIT_BG=1 WAIT_SCRIPT="wait-gups.sh ${RES}/$${PREFIX}_gups_pebs.txt" HEMEM_MGR_START_CPU=0 HEMEM_START_CPU=${FLEXKV_CPUS_START} HEMEM_NUM_CORES=${FLEXKV_THDS} NVMSIZE=$${NVMSIZE} DRAMSIZE=$${DRAMSIZE} PRELOAD="${HEMEM_PRELOAD}" \
		NVMOFFSET=0 DRAMOFFSET=0 FLEXKV_SIZE=$${FLEXKV_SIZE} PREFIX=$${PREFIX}_gups & \
	FLEX_PID=$$!; \
	$(MAKE) run_gups_pebs HEMEM_MGR_START_CPU=2 HEMEM_START_CPU=${APP_CPUS_START} HEMEM_NUM_CORES=${APP_THDS} NVMSIZE=$${NVMSIZE} DRAMSIZE=$${DRAMSIZE} PRELOAD="${HEMEM_PRELOAD}" \
		NVMOFFSET=$${NVMSIZE} DRAMOFFSET=$${DRAMSIZE} \
		APP_SIZE=${GUPS_SIZE} PREFIX=$${PREFIX} & \
	wait $${FLEX_PID}; \
	pkill flexkvs;\
	pkill gups-pebs;\
	pkill perf;\
	${KILL_PERF} \
	${RUN_PERF} \
	$(MAKE) run_flexkvs MAXMEM_MEASURE=1 WAIT_BG=1 WAIT_SCRIPT="wait-gapbs.sh ${RES}/$${PREFIX}_gapbs.txt" HEMEM_MGR_START_CPU=0 HEMEM_START_CPU=${FLEXKV_CPUS_START} HEMEM_NUM_CORES=${FLEXKV_THDS} NVMSIZE=$${NVMSIZE} DRAMSIZE=$${DRAMSIZE} PRELOAD="${HEMEM_PRELOAD}" \
		NVMOFFSET=0 DRAMOFFSET=0 FLEXKV_SIZE=$${FLEXKV_SIZE} PREFIX=$${PREFIX}_gapbs & \
	FLEX_PID=$$!; \
	$(MAKE) run_gapbs HEMEM_MGR_START_CPU=2 HEMEM_START_CPU=${APP_CPUS_START} HEMEM_NUM_CORES=${APP_THDS} NVMSIZE=$${NVMSIZE} DRAMSIZE=$${DRAMSIZE} PRELOAD="${HEMEM_PRELOAD}" \
		NVMOFFSET=$${NVMSIZE} DRAMOFFSET=$${DRAMSIZE} \
		APP_SIZE=${GAPBS_SIZE} PREFIX=$${PREFIX} & \
	wait $${FLEX_PID}; \
	pkill flexkvs;\
	pkill bc;\
	pkill perf;\
	${KILL_PERF} \
	${RUN_PERF} \
	$(MAKE) run_flexkvs MAXMEM_MEASURE=1 WAIT_BG=1 WAIT_SCRIPT="wait-bt.sh ${RES}/$${PREFIX}_bt.txt" HEMEM_MGR_START_CPU=0 HEMEM_START_CPU=${FLEXKV_CPUS_START} HEMEM_NUM_CORES=${FLEXKV_THDS} NVMSIZE=$${NVMSIZE} DRAMSIZE=$${DRAMSIZE} PRELOAD="${HEMEM_PRELOAD}" \
		NVMOFFSET=0 DRAMOFFSET=0 FLEXKV_SIZE=$${FLEXKV_SIZE} PREFIX=$${PREFIX}_bt & \
	FLEX_PID=$$!; \
	$(MAKE) run_bt HEMEM_MGR_START_CPU=2 HEMEM_START_CPU=${APP_CPUS_START} HEMEM_NUM_CORES=${APP_THDS} NVMSIZE=$${NVMSIZE} DRAMSIZE=$${DRAMSIZE} PRELOAD="${HEMEM_PRELOAD}" \
		NVMOFFSET=$${NVMSIZE} DRAMOFFSET=$${DRAMSIZE} \
		BT_SIZE=${BT_SIZE} PREFIX=$${PREFIX} & \
	wait $${FLEX_PID}; \
	pkill flexkvs;\
	pkill bt.E;\
	pkill perf;\
	${KILL_PERF}

# FlexKV occupies the entire DRAM and half of NVM, and other app the other half of NVM
run_test_nodram_bg_sw_tier: all
	# HeMem runs
	FLEXKV_SIZE=$$((${APPSIZE})); \
	NVMSIZE1=$$(($${FLEXKV_SIZE})); \
	NVMSIZE2=$$((${NVMSIZE} - $${FLEXKV_SIZE})); \
	${SETUP_CMD} \
	PREFIX=bg_nodram_test_hemem; \
	file=${RES}/$${PREFIX}_Isolated; \
	${RUN_PERF} \
	$(MAKE) run_flexkvs MAXMEM_MEASURE=1 HEMEM_MGR_START_CPU=0 HEMEM_START_CPU=${FLEXKV_CPUS_START} HEMEM_NUM_CORES=${FLEXKV_THDS} DRAMSIZE=0 DRAMOFFSET=${DRAMSIZE} NVMSIZE=$${NVMSIZE1} NVMOFFSET=0 PRELOAD="${HEMEM_PRELOAD}" \
		FLEXKV_SIZE=$${FLEXKV_SIZE} PREFIX=$${PREFIX}_Isolated; \
	pkill flexkvs;\
	$(MAKE) run_flexkvs MAXMEM_MEASURE=1 WAIT_BG=1 WAIT_SCRIPT="wait-gups.sh ${RES}/$${PREFIX}_gups_pebs.txt" HEMEM_MGR_START_CPU=0 HEMEM_START_CPU=${FLEXKV_CPUS_START} HEMEM_NUM_CORES=${FLEXKV_THDS} DRAMSIZE=0 DRAMOFFSET=${DRAMSIZE} NVMSIZE=$${NVMSIZE1} NVMOFFSET=0 PRELOAD="${HEMEM_PRELOAD}" \
		FLEXKV_SIZE=$${FLEXKV_SIZE} PREFIX=$${PREFIX}_gups & \
	FLEX_PID=$$!; \
	$(MAKE) run_gups_pebs HEMEM_MGR_START_CPU=2 HEMEM_START_CPU=${APP_CPUS_START} HEMEM_NUM_CORES=${APP_THDS} NVMSIZE=$${NVMSIZE2} DRAMSIZE=${DRAMSIZE} NVMOFFSET=$${NVMSIZE1} DRAMOFFSET=0 \
		PRELOAD="${HEMEM_PRELOAD}" APP_SIZE=${GUPS_SIZE} PREFIX=$${PREFIX}& \
	wait $${FLEX_PID}; \
	pkill flexkvs;\
	pkill gups-pebs;\
	pkill perf;\
	${KILL_PERF} \
	${RUN_PERF} \
	$(MAKE) run_flexkvs MAXMEM_MEASURE=1 WAIT_BG=1 WAIT_SCRIPT="wait-gapbs.sh ${RES}/$${PREFIX}_gapbs.txt" HEMEM_MGR_START_CPU=0 HEMEM_START_CPU=${FLEXKV_CPUS_START} HEMEM_NUM_CORES=${FLEXKV_THDS} DRAMSIZE=0 DRAMOFFSET=${DRAMSIZE} NVMSIZE=$${NVMSIZE1} NVMOFFSET=0 PRELOAD="${HEMEM_PRELOAD}" \
		FLEXKV_SIZE=$${FLEXKV_SIZE} PREFIX=$${PREFIX}_gapbs & \
	FLEX_PID=$$!; \
	$(MAKE) run_gapbs HEMEM_MGR_START_CPU=2 HEMEM_START_CPU=${APP_CPUS_START} HEMEM_NUM_CORES=${APP_THDS} NVMSIZE=$${NVMSIZE2} DRAMSIZE=${DRAMSIZE} NVMOFFSET=$${NVMSIZE1} DRAMOFFSET=0 \
		PRELOAD="${HEMEM_PRELOAD}" APP_SIZE=${GAPBS_SIZE} PREFIX=$${PREFIX} & \
	wait $${FLEX_PID}; \
	pkill flexkvs;\
	pkill bc;\
	pkill perf;\
	${KILL_PERF} \
	${RUN_PERF} \
	$(MAKE) run_flexkvs MAXMEM_MEASURE=1 WAIT_BG=1 WAIT_SCRIPT="wait-bt.sh ${RES}/$${PREFIX}_bt.txt" HEMEM_MGR_START_CPU=0 HEMEM_START_CPU=${FLEXKV_CPUS_START} HEMEM_NUM_CORES=${FLEXKV_THDS} DRAMSIZE=0 DRAMOFFSET=${DRAMSIZE} NVMSIZE=$${NVMSIZE1} NVMOFFSET=0 PRELOAD="${HEMEM_PRELOAD}" \
		FLEXKV_SIZE=$${FLEXKV_SIZE} PREFIX=$${PREFIX}_bt & \
	FLEX_PID=$$!; \
	$(MAKE) run_bt HEMEM_MGR_START_CPU=2 HEMEM_START_CPU=${APP_CPUS_START} HEMEM_NUM_CORES=${APP_THDS} NVMSIZE=$${NVMSIZE2} DRAMSIZE=${DRAMSIZE} NVMOFFSET=$${NVMSIZE1} DRAMOFFSET=0 \
		PRELOAD="${HEMEM_PRELOAD}" BT_SIZE=${BT_SIZE} PREFIX=$${PREFIX} & \
	wait $${FLEX_PID}; \
	pkill flexkvs;\
	pkill bt.E;\
	pkill perf;\
	${KILL_PERF}

# FlexKV occupies the entire DRAM and half of NVM, and other app the other half of NVM
run_test_bg_sw_tier: all
	# HeMem runs
	FLEXKV_SIZE=$$((${APPSIZE})); \
	NVMSIZE=$$((${NVMSIZE}/2)); \
	${SETUP_CMD} \
	PREFIX=bg_test_hemem; \
	file=${RES}/$${PREFIX}_Isolated; \
	${RUN_PERF} \
	$(MAKE) run_flexkvs MAXMEM_MEASURE=1 HEMEM_MGR_START_CPU=0 HEMEM_START_CPU=${FLEXKV_CPUS_START} HEMEM_NUM_CORES=${FLEXKV_THDS} DRAMSIZE=${DRAMSIZE} DRAMOFFSET=0 NVMSIZE=$${NVMSIZE} NVMOFFSET=0 PRELOAD="${HEMEM_PRELOAD}" \
		FLEXKV_SIZE=$${FLEXKV_SIZE} PREFIX=$${PREFIX}_Isolated; \
	pkill flexkvs;\
	$(MAKE) run_flexkvs MAXMEM_MEASURE=1 WAIT_BG=1 WAIT_SCRIPT="wait-gups.sh ${RES}/$${PREFIX}_gups_pebs.txt" HEMEM_MGR_START_CPU=0 HEMEM_START_CPU=${FLEXKV_CPUS_START} HEMEM_NUM_CORES=${FLEXKV_THDS} DRAMSIZE=${DRAMSIZE} DRAMOFFSET=0 NVMSIZE=$${NVMSIZE} NVMOFFSET=0 PRELOAD="${HEMEM_PRELOAD}" \
		FLEXKV_SIZE=$${FLEXKV_SIZE} PREFIX=$${PREFIX}_gups & \
	FLEX_PID=$$!; \
	$(MAKE) run_gups_pebs HEMEM_MGR_START_CPU=2 HEMEM_START_CPU=${APP_CPUS_START} HEMEM_NUM_CORES=${APP_THDS} NVMSIZE=$${NVMSIZE} DRAMSIZE=0 NVMOFFSET=$${NVMSIZE} DRAMOFFSET=${DRAMSIZE} \
		PRELOAD="${HEMEM_PRELOAD}" APP_SIZE=${GUPS_SIZE} PREFIX=$${PREFIX}& \
	wait $${FLEX_PID}; \
	pkill flexkvs;\
	pkill gups-pebs;\
	pkill perf;\
	${KILL_PERF} \
	${RUN_PERF} \
	$(MAKE) run_flexkvs MAXMEM_MEASURE=1 WAIT_BG=1 WAIT_SCRIPT="wait-gapbs.sh ${RES}/$${PREFIX}_gapbs.txt" HEMEM_MGR_START_CPU=0 HEMEM_START_CPU=${FLEXKV_CPUS_START} HEMEM_NUM_CORES=${FLEXKV_THDS} DRAMSIZE=${DRAMSIZE} DRAMOFFSET=0 NVMSIZE=$${NVMSIZE} NVMOFFSET=0 PRELOAD="${HEMEM_PRELOAD}" \
		FLEXKV_SIZE=$${FLEXKV_SIZE} PREFIX=$${PREFIX}_gapbs & \
	FLEX_PID=$$!; \
	$(MAKE) run_gapbs HEMEM_MGR_START_CPU=2 HEMEM_START_CPU=${APP_CPUS_START} HEMEM_NUM_CORES=${APP_THDS} NVMSIZE=$${NVMSIZE} DRAMSIZE=0 NVMOFFSET=$${NVMSIZE} DRAMOFFSET=${DRAMSIZE} \
		PRELOAD="${HEMEM_PRELOAD}" APP_SIZE=${GAPBS_SIZE} PREFIX=$${PREFIX} & \
	wait $${FLEX_PID}; \
	pkill flexkvs;\
	pkill bc;\
	pkill perf;\
	${KILL_PERF} \
	${RUN_PERF} \
	$(MAKE) run_flexkvs MAXMEM_MEASURE=1 WAIT_BG=1 WAIT_SCRIPT="wait-bt.sh ${RES}/$${PREFIX}_bt.txt" HEMEM_MGR_START_CPU=0 HEMEM_START_CPU=${FLEXKV_CPUS_START} HEMEM_NUM_CORES=${FLEXKV_THDS} DRAMSIZE=${DRAMSIZE} DRAMOFFSET=0 NVMSIZE=$${NVMSIZE} NVMOFFSET=0 PRELOAD="${HEMEM_PRELOAD}" \
		FLEXKV_SIZE=$${FLEXKV_SIZE} PREFIX=$${PREFIX}_bt & \
	FLEX_PID=$$!; \
	$(MAKE) run_bt HEMEM_MGR_START_CPU=2 HEMEM_START_CPU=${APP_CPUS_START} HEMEM_NUM_CORES=${APP_THDS} NVMSIZE=$${NVMSIZE} DRAMSIZE=0 NVMOFFSET=$${NVMSIZE} DRAMOFFSET=${DRAMSIZE} \
		PRELOAD="${HEMEM_PRELOAD}" BT_SIZE=${BT_SIZE} PREFIX=$${PREFIX} & \
	wait $${FLEX_PID}; \
	pkill flexkvs;\
	pkill bt.E;\
	pkill perf;\
	${KILL_PERF}

# FlexKV's working set fits into DRAM. DRAM is split equally between FlexKV and other app
run_bg_mini_sw_tier: all
	# HeMem runs
	FLEXKV_SIZE=$$((64*1024*1024*1024)); \
	NVMSIZE=$$((${NVMSIZE}/2)); DRAMSIZE=$$((${DRAMSIZE}/2)); \
	${SETUP_CMD} \
	PREFIX=bg_mini_hemem; \
	$(MAKE) run_flexkvs NVMSIZE=$${NVMSIZE} DRAMSIZE=$${DRAMSIZE} NVMOFFSET=0 DRAMOFFSET=0 \
		PRELOAD="${HEMEM_PRELOAD}" FLEXKV_SIZE=$${FLEXKV_SIZE} PREFIX=$${PREFIX}_Isolated; \
	pkill flexkvs;\
	$(MAKE) run_flexkvs NVMSIZE=$${NVMSIZE} DRAMSIZE=$${DRAMSIZE} NVMOFFSET=0 DRAMOFFSET=0 \
		PRELOAD="${HEMEM_PRELOAD}" FLEXKV_SIZE=$${FLEXKV_SIZE} PREFIX=$${PREFIX}_gups & \
	$(MAKE) run_gups_pebs NVMSIZE=$${NVMSIZE} DRAMSIZE=$${DRAMSIZE} \
		NVMOFFSET=$${NVMSIZE} DRAMOFFSET=$${DRAMSIZE} \
		PRELOAD="${HEMEM_PRELOAD}" APP_SIZE=${GUPS_SIZE} PREFIX=$${PREFIX}; \
	wait; \
	pkill flexkvs;\
	$(MAKE) run_gapbs NVMSIZE=$${NVMSIZE} DRAMSIZE=$${DRAMSIZE} \
		NVMOFFSET=$${NVMSIZE} DRAMOFFSET=$${DRAMSIZE} \
		PRELOAD="${HEMEM_PRELOAD}" APP_SIZE=${GAPBS_SIZE} PREFIX=$${PREFIX} & \
	$(MAKE) run_flexkvs NVMSIZE=$${NVMSIZE} DRAMSIZE=$${DRAMSIZE} NVMOFFSET=0 DRAMOFFSET=0 \
		PRELOAD="${HEMEM_PRELOAD}" FLEXKV_SIZE=$${FLEXKV_SIZE} PREFIX=$${PREFIX}_gapbs; \
	wait;\
	pkill flexkvs;\
	$(MAKE) run_flexkvs NVMSIZE=$${NVMSIZE} DRAMSIZE=$${DRAMSIZE} NVMOFFSET=0 DRAMOFFSET=0 \
		PRELOAD="${HEMEM_PRELOAD}" FLEXKV_SIZE=$${FLEXKV_SIZE} PREFIX=$${PREFIX}_bt & \
	$(MAKE) run_bt NVMSIZE=$${NVMSIZE} DRAMSIZE=$${DRAMSIZE} \
		NVMOFFSET=$${NVMSIZE} DRAMOFFSET=$${DRAMSIZE} \
		PRELOAD="${HEMEM_PRELOAD}" BT_SIZE=${BT_SIZE} PREFIX=$${PREFIX}; \
	wait; \
	pkill flexkvs;

# FlexKV occupies first half of DRAM/NVM, and other app the other half	
run_eval_apps: all	
	# HeMem runs	
	FLEXKV_SIZE=$$((${APPSIZE})); \
	${SETUP_CMD} \
	PREFIX=eval_qtmem; \
	${RUN_PERF} \
	file=${RES}/$${PREFIX}_Isolated; \
	${RUN_MGR} \
	$(MAKE) run_flexkvs PRELOAD="${HEMEM_PRELOAD}" FLEXKV_SIZE=$${FLEXKV_SIZE} PREFIX=$${PREFIX}_Isolated; \
	${KILL_MGR} \
	file=${RES}/$${PREFIX}_gups_fkvs; \
	${RUN_MGR} \
	$(MAKE) run_flexkvs PRELOAD="${HEMEM_PRELOAD}" FLEXKV_SIZE=$${FLEXKV_SIZE} PREFIX=$${PREFIX}_gups & \
	FLEX_PID=$$!; \
	$(MAKE) run_gups_pebs PRELOAD="${HEMEM_PRELOAD}" APP_SIZE=${GUPS_SIZE} PREFIX=$${PREFIX} & \
	wait $${FLEX_PID}; \
	${KILL_MGR} \
	file=${RES}/$${PREFIX}_gapbs_fkvs; \
	${RUN_MGR} \
	$(MAKE) run_gapbs PRELOAD="${HEMEM_PRELOAD}" APP_SIZE=${GAPBS_SIZE} PREFIX=$${PREFIX} & \
	GAPBS_PID=$$!; \
	$(MAKE) run_flexkvs PRELOAD="${HEMEM_PRELOAD}" FLEXKV_SIZE=$${FLEXKV_SIZE} PREFIX=$${PREFIX}_gapbs; \
	${KILL_MGR} \
	file=${RES}/$${PREFIX}_bt_fkvs; \
	${RUN_MGR} \
	$(MAKE) run_flexkvs PRELOAD="${HEMEM_PRELOAD}" FLEXKV_SIZE=$${FLEXKV_SIZE} PREFIX=$${PREFIX}_bt & \
	FLEX_PID=$$!; \
	$(MAKE) run_bt PRELOAD="${HEMEM_PRELOAD}" BT_SIZE=${BT_SIZE} PREFIX=$${PREFIX} & \
	wait $${FLEX_PID}; \
	${KILL_MGR} \
	${KILL_PERF}

run_eval_dynamic: all
	# qtMem runs
	FLEXKV_SIZE=$$((${APPSIZE})); \
	FLEXKV_RUNTIME=160; \
	FLEXKV_HOT_FRAC=0.15; \
	FLEXKV_HOT_FRAC2=0.30; \
	GUPS_SIZE=$$((128*1024*1024*1024)); \
	GAPBS_SIZE=28; \
	APP_THREADS=4; \
	GAPBS_CPUS=5-10; \
	GUPS_CPUS=11-16; \
	${SETUP_CMD} \
	PREFIX=dynamic; \
	${RUN_PERF} \
	${RUN_MGR} \
	$(MAKE) run_flexkvs_grow PRELOAD="${HEMEM_PRELOAD}" FLEXKV_RUNTIME=$${FLEXKV_RUNTIME} FLEXKV_HOT_FRAC=$${FLEXKV_HOT_FRAC} FLEXKV_HOT_FRAC2=$${FLEXKV_HOT_FRAC2} FLEXKV_SIZE=$${FLEXKV_SIZE} PREFIX=$${PREFIX}_qtMem & \
	FLEX_PID=$$!; \
	$(MAKE) run_gapbs APP_THDS=$${APP_THREADS} APP_CPUS=$${GAPBS_CPUS} PRELOAD="${HEMEM_PRELOAD}" APP_SIZE=$${GAPBS_SIZE} PREFIX=$${PREFIX} & \
	GAPBS_PID=$$!; \
	sleep 560; \
	$(MAKE) run_gups_pebs APP_THDS=$${APP_THREADS} APP_CPUS=$${GUPS_CPUS} PRELOAD="${HEMEM_PRELOAD}" APP_SIZE=$${GUPS_SIZE} PREFIX=$${PREFIX} & \
	GUPS_PID=$$!; \
	sleep 240; \
	echo Done; \
	kill -9 $${GAPBS_PID}; \
	kill -9 $${GUPS_PID}; \
	kill -9 $${FLEX_PID}; \
	${KILL_MGR} \
	${KILL_PERF}

run_eval_dynamic_hemem: all
	# qtMem runs
	FLEXKV_SIZE=$$((${APPSIZE})); \
	FLEXKV_RUNTIME=160; \
	FLEXKV_HOT_FRAC=0.15; \
	FLEXKV_HOT_FRAC2=0.30; \
	GUPS_SIZE=$$((128*1024*1024*1024)); \
	GAPBS_SIZE=28; \
	APP_THREADS=4; \
	GAPBS_CPUS=5-10; \
	GUPS_CPUS=11-16; \
	NVMSIZE1=$$((278*1024*1024*1024)); DRAMSIZE=$$((42*1024*1024*1024)); \
	NVMSIZE2=$$((117*1024*1024*1024)); \
	${SETUP_CMD} \
	PREFIX=dynamic; \
	$(MAKE) run_flexkvs_grow NVMSIZE=$${NVMSIZE1} DRAMSIZE=$${DRAMSIZE} NVMOFFSET=$$(($${NVMSIZE2} * 2)) DRAMOFFSET=$$(($${DRAMSIZE}*2)) PRELOAD="${HEMEM_PRELOAD}" FLEXKV_RUNTIME=$${FLEXKV_RUNTIME} FLEXKV_HOT_FRAC=$${FLEXKV_HOT_FRAC} FLEXKV_HOT_FRAC2=$${FLEXKV_HOT_FRAC2} FLEXKV_SIZE=$${FLEXKV_SIZE} PREFIX=$${PREFIX}_HeMem & \
	FLEX_PID=$$!; \
	$(MAKE) run_gapbs NVMSIZE=$${NVMSIZE2} DRAMSIZE=$${DRAMSIZE} NVMOFFSET=0 DRAMOFFSET=0 APP_THDS=$${APP_THREADS} APP_CPUS=$${GAPBS_CPUS} PRELOAD="${HEMEM_PRELOAD}" APP_SIZE=$${GAPBS_SIZE} PREFIX=$${PREFIX} & \
	GUPS_PID=$$!; \
	sleep 560; \
	$(MAKE) run_gups_pebs NVMSIZE=$${NVMSIZE2} DRAMSIZE=$${DRAMSIZE} NVMOFFSET=$${NVMSIZE2} DRAMOFFSET=$${DRAMSIZE} APP_THDS=$${APP_THREADS} APP_CPUS=$${GUPS_CPUS} PRELOAD="${HEMEM_PRELOAD}" APP_SIZE=$${GUPS_SIZE} PREFIX=$${PREFIX} & \
	GAPBS_PID=$$!; \
	sleep 240; \
	echo Done; \
	kill -9 $${GAPBS_PID}; \
	kill -9 $${GUPS_PID}; \
	kill -9 $${FLEX_PID}; \
	pkill bc; \
	pkill gups-pebs; \
	pkill kvsbench; \
	pkill flexkvs;


run_eval_dynamic_znuma: all
	BASE_NODE=1;\
	FLEXKV_SIZE=$$((${APPSIZE})); \
	FLEXKV_RUNTIME=160; \
	FLEXKV_HOT_FRAC=0.15; \
	FLEXKV_HOT_FRAC2=0.30; \
	GUPS_SIZE=$$((128*1024*1024*1024)); \
	GAPBS_SIZE=28; \
	APP_THREADS=4; \
	GAPBS_CPUS=5-10; \
	GUPS_CPUS=11-16; \
	PREFIX=dynamic; \
	$(MAKE) run_flexkvs_grow BASE_NODE=$${BASE_NODE} NUMA_CMD="$${NUMA_CMD}" PRELOAD="" FLEXKV_RUNTIME=$${FLEXKV_RUNTIME} FLEXKV_HOT_FRAC=$${FLEXKV_HOT_FRAC} FLEXKV_HOT_FRAC2=$${FLEXKV_HOT_FRAC2} FLEXKV_SIZE=$${FLEXKV_SIZE} PREFIX=$${PREFIX}_znuma & \
	FLEX_PID=$$!; \
	$(MAKE) run_gapbs BASE_NODE=$${BASE_NODE} NUMA_CMD="$${NUMA_CMD}" APP_THDS=$${APP_THREADS} APP_CPUS=$${GAPBS_CPUS} PRELOAD="" APP_SIZE=$${GAPBS_SIZE} PREFIX=$${PREFIX} & \
	GUPS_PID=$$!; \
	sleep 560; \
	$(MAKE) run_gups_pebs BASE_NODE=$${BASE_NODE} NUMA_CMD="$${NUMA_CMD}" APP_THDS=$${APP_THREADS} APP_CPUS=$${GUPS_CPUS} PRELOAD="" APP_SIZE=$${GUPS_SIZE} PREFIX=$${PREFIX} & \
	GAPBS_PID=$$!; \
	sleep 240; \
	echo Done; \
	kill -9 $${GAPBS_PID}; \
	kill -9 $${GUPS_PID}; \
	kill -9 $${FLEX_PID}; \
	pkill bc; \
	pkill gups-pebs; \
	pkill kvsbench; \
	pkill flexkvs;


run_eval_dynamic_hw: all
	FLEXKV_SIZE=$$((${APPSIZE})); \
	GUPS_SIZE=$$((64*1024*1024*1024)); \
	GAPBS_SIZE=27; \
	APP_THREADS=4; \
	GAPBS_CPUS=5-10; \
	GUPS_CPUS=11-16; \
	PREFIX=dynamic; \
	$(MAKE) run_flexkvs PRELOAD="" FLEXKV_HOT_FRAC=0.33 FLEXKV_SIZE=$${FLEXKV_SIZE} PREFIX=$${PREFIX}_2LM & \
	FLEX_PID=$$!; \
	$(MAKE) run_gapbs APP_THDS=$${APP_THREADS} APP_CPUS=$${GAPBS_CPUS} PRELOAD="" APP_SIZE=$${GAPBS_SIZE} PREFIX=$${PREFIX} & \
	GUPS_PID=$$!; \
	sleep 560; \
	$(MAKE) run_gups APP_THDS=$${APP_THREADS} APP_CPUS=$${GUPS_CPUS} PRELOAD="" APP_SIZE=$${GUPS_SIZE} PREFIX=$${PREFIX} & \
	GAPBS_PID=$$!; \
	sleep 180; \
	echo Done; \
	kill -9 $${GAPBS_PID}; \
	kill -9 $${GUPS_PID}; \
	kill -9 $${FLEX_PID}; \
	pkill bc; \
	pkill gups; \
	pkill kvsbench; \
	pkill flexkvs;

#BG_PREFIXES = "bg_dram_base,bg_hw_tier,bg_znuma_tier,bg_mini_hemem,bg_hemem,bg_test_hemem"
BG_PREFIXES = "bg_dram_base,bg_mini_hemem,bg_hemem,bg_test_hemem,bg_nodram_test_hemem"
BG_APPS = "Isolated,gups,gapbs,bt"
extract_bg: all
	python scripts/extract_script.py ${BG_PREFIXES} ${BG_APPS} ${RES}

extract_bg_timeline: all
	python scripts/extract_timeline.py ${BG_PREFIXES} ${BG_APPS} ${RES}

EVAL_PREFIXES = "eval_qtmem"
EVAL_APPS = "Isolated,gups,gapbs,bt"
extract_eval: all
	python scripts/extract_script.py ${EVAL_PREFIXES} ${EVAL_APPS} ${RES}

extract_eval_timeline: all
	python scripts/extract_timeline.py ${EVAL_PREFIXES} ${EVAL_APPS} ${RES}

DYNAMIC_PREFIXES = "dynamic"
DYNAMIC_APPS="qtMem,HeMem,znuma"
extract_dynamic: all
	python scripts/extract_script.py ${DYNAMIC_PREFIXES} ${DYNAMIC_APPS} ${RES}

extract_dynamic_timeline: all
	python scripts/extract_dynamic_timeline.py ${DYNAMIC_PREFIXES} ${DYNAMIC_APPS} ${RES}


