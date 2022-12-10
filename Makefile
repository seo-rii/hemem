.PHONY: all Hoard HeMem GUPS FlexKVS GAPBS\
	run_flexkvs run_gups run_gapbs run_bt \
	run_bg_dram_base run_bg_hw_tier run_bg_sw_tier \
	 

default: all

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
NUMA_CMD ?= numactl -N${BASE_NODE} -m${BASE_NODE}
NUMA_CMD_CLIENT ?= numactl -N${OTHER_NODE} -m${OTHER_NODE}
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
NVMSIZE    ?= $$((512*1024*1024*1024))
DRAMSIZE   ?= $$((128*1024*1024*1024))
NVMOFFSET  ?= 0
DRAMOFFSET ?= 0

# Configs for app runs
FLEXKV_THDS ?= 4
APP_THDS    ?= 8
ifeq (${BASE_NODE}, 1)
MGR_CPUS    ?= 24-31
APP_CPUS    ?= 32-41
FLEXKV_CPUS ?= 42-47
else
MGR_CPUS    ?= 0-7
APP_CPUS    ?= 8-17
FLEXKV_CPUS ?= 18-23
endif

FLEXKV_SIZE ?= $$((64*1024*1024*1024))
GUPS_SIZE   ?= $$((256*1024*1024*1024))
GAPBS_SIZE  ?= 28
BT_SIZE     ?= $$((168*1024*1024*1024))

FLEXKV_PRTY ?= ${SET_HIGH_PRTY}
GUPS_PRTY   ?= ${SET_LOW_PRTY}
GAPBS_PRTY  ?= ${SET_LOW_PRTY}

# Commands needed by HeMem
SETUP_CMD = export LD_LIBRARY_PATH=./src:./Hoard/src:$LD_LIBRARY_PATH; \
	echo 1000000 > /proc/sys/vm/max_map_count;
HEMEM_PRELOAD = env LD_PRELOAD=./src/libhemem.so

RUN_MGR = nice -20 ${NUMA_CMD} --physcpubind=${MGR_CPUS} ./src/central-manager & \
	CTRL_MGR=$$!; \
	sleep 20;

KILL_MGR = kill $${CTRL_MGR}; sleep 5;

RUN_PERF = while : ; \
	do \
		perf stat -e mem_load_l3_miss_retired.local_dram,mem_load_retired.local_pmm & \
		perf_pid=$$!; \
		sleep 1; \
		kill -9 $${perf_pid}; \
	done & \
	PERF_CMD=$$!;

KILL_PERF = kill $${PERF_CMD}; sleep 5;

FLEXKV_NICE ?= nice -20
FLEXKV_SERVER_WAIT ?= 120
FLEXKV_SAMPLE_TIME ?= 600
FLEXKV_HOT_FRAC ?= 0.25
# TODO: Can we somehow launch client after server is setup
# instead of waiting an arbitrary amount of time and hoping
# that the server is ready in that time?
run_flexkvs: ./apps/flexkvs/flexkvs ./apps/flexkvs/kvsbench
	-./apps/flexkvs/unlink_socks.sh; # Cleanup

	${FLEXKV_PRTY} ${FLEXKV_NICE} ${NUMA_CMD} --physcpubind=${FLEXKV_CPUS} \
		${PRELOAD} ./apps/flexkvs/flexkvs flexkvs.conf ${FLEXKV_THDS} ${FLEXKV_SIZE} & \
	sleep ${FLEXKV_SERVER_WAIT}; \
	${FLEXKV_NICE} ${NUMA_CMD_CLIENT} \
		./apps/flexkvs/kvsbench -t ${FLEXKV_THDS} -T ${FLEXKV_SAMPLE_TIME} \
		-h ${FLEXKV_HOT_FRAC} 127.0.0.1:11211 -S $$((15*${FLEXKV_SIZE}/16)) > ${RES}/${PREFIX}_flexkv.txt;

GUPS_ITERS ?= 4000000000
run_gups: ./microbenchmarks/gups
	log_size=$$(printf "%.0f" $$(echo "l(${APP_SIZE})/l(2)"|bc -l)); \
	${GUPS_PRTY} ${NUMA_CMD} --physcpubind=${APP_CPUS} \
		./microbenchmarks/gups ${APP_THDS} ${GUPS_ITERS} $${log_size} \
		8 $${log_size} > ${RES}/${PREFIX}_gups.txt;

run_gups_pebs: ./microbenchmarks/gups-pebs
	log_size=$$(printf "%.0f" $$(echo "l(${APP_SIZE})/l(2)"|bc -l)); \
	NVMSIZE=${NVMSIZE} DRAMSIZE=${DRAMSIZE} \
	NVMOFFSET=${NVMOFFSET} DRAMOFFSET=${DRAMOFFSET} \
	${GUPS_PRTY} ${NUMA_CMD} --physcpubind=${APP_CPUS} ${PRELOAD} \
		./microbenchmarks/gups-pebs ${APP_THDS} ${GUPS_ITERS} \
		$${log_size} 8 $${log_size} > ${RES}/${PREFIX}_gups_pebs.txt;

GAPBS_TRIALS ?= 15
run_gapbs: ./apps/gapbs/bc
	NVMSIZE=${NVMSIZE} DRAMSIZE=${DRAMSIZE} NVMOFFSET=${NVMOFFSET} \
	DRAMOFFSET=${DRAMOFFSET} OMP_THREAD_LIMIT=${APP_THDS} \
	${GAPBS_PRTY} ${NUMA_CMD} --physcpubind=${APP_CPUS} ${PRELOAD} \
		./apps/gapbs/bc -n ${GAPBS_TRIALS} -g ${APP_SIZE} > ${RES}/${PREFIX}_gapbs.txt;

# TODO: Command to run BT
run_bt: 
	# NVMSIZE=${NVMSIZE} DRAMSIZE=${DRAMSIZE} \
	#	NVMOFFSET=${NVMOFFSET} DRAMOFFSET=${DRAMOFFSET} \
	#	${PRELOAD} ${NUMA_CMD} --physcpubind=${APP_CPUS} \
	#	./bt > ${RES}/${PREFIX}_bt.txt;

run_bg_dram_base: all
	PREFIX=bg_dram_base; \
	BASE_NODE=1;\
	APP_SIZE=$$((64*1024*1024*1024)); \
	$(MAKE) run_flexkvs BASE_NODE=$${BASE_NODE} PRELOAD="" \
		FLEXKV_SIZE=$${APP_SIZE} PREFIX=$${PREFIX}_Isolated; \
	wait;\
	$(MAKE) run_flexkvs BASE_NODE=$${BASE_NODE} PRELOAD="" \
		FLEXKV_SIZE=$${APP_SIZE} PREFIX=$${PREFIX}_gups & \
	$(MAKE) run_gups BASE_NODE=$${BASE_NODE} APP_SIZE=$${APP_SIZE} \
		GUPS_ITERS=$$((${GUPS_ITERS} * 2)) PREFIX=$${PREFIX}; \
	wait;\
	$(MAKE) run_gapbs BASE_NODE=$${BASE_NODE} PRELOAD="" APP_SIZE=27 \
		GAPBS_TRIALS=$$((${GAPBS_TRIALS} * 3)) PREFIX=$${PREFIX} & \
	sleep 300; \
	$(MAKE) run_flexkvs BASE_NODE=$${BASE_NODE} PRELOAD="" \
		FLEXKV_SIZE=$${APP_SIZE} PREFIX=$${PREFIX}_gapbs; \
	wait;

run_bg_hw_tier: all
	PREFIX=bg_hw_tier; \
	FLEXKV_SIZE=$$((320*1024*1024*1024)); \
	$(MAKE) run_flexkvs FLEXKV_SIZE=$${FLEXKV_SIZE} PRELOAD="" PREFIX=$${PREFIX}_Isolated; \
	$(MAKE) run_flexkvs FLEXKV_SIZE=$${FLEXKV_SIZE} PRELOAD="" PREFIX=$${PREFIX}_gups & \
	$(MAKE) run_gups APP_SIZE=${GUPS_SIZE} PREFIX=$${PREFIX}; \
	wait; \
	$(MAKE) run_gapbs PRELOAD="" APP_SIZE=${GAPBS_SIZE} GAPBS_TRIALS=$$((${GAPBS_TRIALS} * 3)) PREFIX=$${PREFIX} & \
	sleep 600; \
	$(MAKE) run_flexkvs FLEXKV_SIZE=$${FLEXKV_SIZE} PRELOAD="" PREFIX=$${PREFIX}_gapbs; \
	wait;

# FlexKV occupies first half of DRAM/NVM, and other app the other half
run_bg_sw_tier: all
	# HeMem runs
	FLEXKV_SIZE=$$((320*1024*1024*1024)); \
	NVMSIZE=$$((${NVMSIZE}/2)); DRAMSIZE=$$((${DRAMSIZE}/2)); \
	${SETUP_CMD} \
	PREFIX=bg_hemem; \
	$(MAKE) run_flexkvs NVMSIZE=$${NVMSIZE} DRAMSIZE=$${DRAMSIZE} PRELOAD="${HEMEM_PRELOAD}" \
		NVMOFFSET=0 DRAMOFFSET=0 FLEXKV_SIZE=$${FLEXKV_SIZE} PREFIX=$${PREFIX}_Isolated; \
	$(MAKE) run_flexkvs NVMSIZE=$${NVMSIZE} DRAMSIZE=$${DRAMSIZE} PRELOAD="${HEMEM_PRELOAD}" \
		NVMOFFSET=0 DRAMOFFSET=0 FLEXKV_SIZE=$${FLEXKV_SIZE} PREFIX=$${PREFIX}_gups & \
	$(MAKE) run_gups_pebs NVMSIZE=$${NVMSIZE} DRAMSIZE=$${DRAMSIZE} PRELOAD="${HEMEM_PRELOAD}" \
		NVMOFFSET=$${NVMSIZE} DRAMOFFSET=$${DRAMSIZE} \
		APP_SIZE=${GUPS_SIZE} PREFIX=$${PREFIX}; \
	wait; \
	$(MAKE) run_gapbs NVMSIZE=$${NVMSIZE} DRAMSIZE=$${DRAMSIZE} PRELOAD="${HEMEM_PRELOAD}" \
		NVMOFFSET=$${NVMSIZE} DRAMOFFSET=$${DRAMSIZE} \
		APP_SIZE=${GAPBS_SIZE} PREFIX=$${PREFIX} & \
	sleep 1200; # Generate graph time \
	$(MAKE) run_flexkvs NVMSIZE=$${NVMSIZE} DRAMSIZE=$${DRAMSIZE} PRELOAD="${HEMEM_PRELOAD}" \
		NVMOFFSET=0 DRAMOFFSET=0 FLEXKV_SIZE=$${FLEXKV_SIZE} PREFIX=$${PREFIX}_gapbs; \
	wait;

# FlexKV occupies the entire DRAM and half of NVM, and other app the other half of NVM
run_test_bg_sw_tier: all
	# HeMem runs
	FLEXKV_SIZE=$$((320*1024*1024*1024)); \
	NVMSIZE=$$((${NVMSIZE}/2)); \
	${SETUP_CMD} \
	PREFIX=bg_test_hemem; \
	#$(MAKE) run_flexkvs NVMSIZE=$${NVMSIZE} NVMOFFSET=0 PRELOAD="${HEMEM_PRELOAD}" \
	#	FLEXKV_SIZE=$${FLEXKV_SIZE} PREFIX=$${PREFIX}_Isolated; \
	#$(MAKE) run_flexkvs NVMSIZE=$${NVMSIZE} NVMOFFSET=0 PRELOAD="${HEMEM_PRELOAD}" \
	#	FLEXKV_SIZE=$${FLEXKV_SIZE} PREFIX=$${PREFIX}_gups & \
	#$(MAKE) run_gups_pebs NVMSIZE=$${NVMSIZE} DRAMSIZE=0 NVMOFFSET=$${NVMSIZE} DRAMOFFSET=$${DRAMSIZE} \
	#	PRELOAD="${HEMEM_PRELOAD}" APP_SIZE=${GUPS_SIZE} PREFIX=$${PREFIX}; \
	#wait; \
	$(MAKE) run_gapbs NVMSIZE=$${NVMSIZE} DRAMSIZE=0 NVMOFFSET=$${NVMSIZE} DRAMOFFSET=$${DRAMSIZE} \
		PRELOAD="${HEMEM_PRELOAD}" APP_SIZE=${GAPBS_SIZE} PREFIX=$${PREFIX} & \
	sleep 600; \
	$(MAKE) run_flexkvs NVMSIZE=$${NVMSIZE} NVMOFFSET=0 PRELOAD="${HEMEM_PRELOAD}" \
		FLEXKV_SIZE=$${FLEXKV_SIZE} PREFIX=$${PREFIX}_gapbs; \
	wait;

# FlexKV's working set fits into DRAM. DRAM is split equally between FlexKV and other app
run_bg_mini_sw_tier: all
	# HeMem runs
	FLEXKV_SIZE=$$((64*1024*1024*1024)); \
	NVMSIZE=$$((${NVMSIZE}/2)); DRAMSIZE=$$((${DRAMSIZE}/2)); \
	${SETUP_CMD} \
	PREFIX=bg_mini_hemem; \
	$(MAKE) run_flexkvs NVMSIZE=$${NVMSIZE} DRAMSIZE=$${DRAMSIZE} NVMOFFSET=0 DRAMOFFSET=0 \
		PRELOAD="${HEMEM_PRELOAD}" FLEXKV_SIZE=$${FLEXKV_SIZE} PREFIX=$${PREFIX}_Isolated; \
	$(MAKE) run_flexkvs NVMSIZE=$${NVMSIZE} DRAMSIZE=$${DRAMSIZE} NVMOFFSET=0 DRAMOFFSET=0 \
		PRELOAD="${HEMEM_PRELOAD}" FLEXKV_SIZE=$${FLEXKV_SIZE} PREFIX=$${PREFIX}_gups & \
	$(MAKE) run_gups_pebs NVMSIZE=$${NVMSIZE} DRAMSIZE=$${DRAMSIZE} \
		NVMOFFSET=$${NVMSIZE} DRAMOFFSET=$${DRAMSIZE} \
		PRELOAD="${HEMEM_PRELOAD}" APP_SIZE=${GUPS_SIZE} PREFIX=$${PREFIX}; \
	wait; \
	$(MAKE) run_gapbs NVMSIZE=$${NVMSIZE} DRAMSIZE=$${DRAMSIZE} \
		NVMOFFSET=$${NVMSIZE} DRAMOFFSET=$${DRAMSIZE} \
		PRELOAD="${HEMEM_PRELOAD}" APP_SIZE=${GAPBS_SIZE} PREFIX=$${PREFIX} & \
	sleep 1200; \
	$(MAKE) run_flexkvs NVMSIZE=$${NVMSIZE} DRAMSIZE=$${DRAMSIZE} NVMOFFSET=0 DRAMOFFSET=0 \
		PRELOAD="${HEMEM_PRELOAD}" FLEXKV_SIZE=$${FLEXKV_SIZE} PREFIX=$${PREFIX}_gapbs; \
	wait;

# FlexKV occupies first half of DRAM/NVM, and other app the other half	
run_eval_apps: all	
	# HeMem runs	
	FLEXKV_SIZE=$$((320*1024*1024*1024)); \
	${SETUP_CMD} \
	PREFIX=eval_qtmem; \
	${RUN_PERF} \
	${RUN_MGR} \
	$(MAKE) run_flexkvs PRELOAD="${HEMEM_PRELOAD}" FLEXKV_SIZE=$${FLEXKV_SIZE} PREFIX=$${PREFIX}_Isolated; \
	${KILL_MGR} \
	${RUN_MGR} \
	$(MAKE) run_flexkvs PRELOAD="${HEMEM_PRELOAD}" FLEXKV_SIZE=$${FLEXKV_SIZE} PREFIX=$${PREFIX}_gups & \
	FLEX_PID=$$!; \
	$(MAKE) run_gups_pebs PRELOAD="${HEMEM_PRELOAD}" APP_SIZE=${GUPS_SIZE} PREFIX=$${PREFIX}; \
	wait $${FLEX_PID}; \
	${KILL_MGR} \
	${RUN_MGR} \
	$(MAKE) run_gapbs PRELOAD="${HEMEM_PRELOAD}" APP_SIZE=${GAPBS_SIZE} PREFIX=$${PREFIX} & \
	GAPBS_PID=$$!; \
	sleep 1200; \
	$(MAKE) run_flexkvs PRELOAD="${HEMEM_PRELOAD}" FLEXKV_SIZE=$${FLEXKV_SIZE} PREFIX=$${PREFIX}_gapbs; \
	wait $${GAPBS_PID}; \
	${KILL_MGR} \
	${KILL_PERF}


BG_PREFIXES = "bg_dram_base,bg_hw_tier,bg_mini_hemem,bg_hemem,bg_test_hemem"
BG_APPS = "Isolated,gups,gapbs"
extract_bg: all
	python extract_script.py ${BG_PREFIXES} ${BG_APPS} ${RES}

EVAL_PREFIXES = "eval_qtmem"
EVAL_APPS = "Isolated,gups,gapbs"
extract_eval: all
	python extract_script.py ${EVAL_PREFIXES} ${EVAL_APPS} ${RES}

extract_eval_timeline: all
	python extract_timeline.py ${EVAL_PREFIXES} ${EVAL_APPS} ${RES}