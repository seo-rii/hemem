# HeMem + colloid

This is a fork of [HeMem](https://bitbucket.org/ajaustin/hemem/src/master/) with [colloid](https://github.com/webglider/colloid/) integration. Please refer to `README-original` for vanilla HeMem documentation. Here, we provide an overview of colloid implementation on top of HeMem along with detailed instructions on how to setup and run the end-to-end system.

## Overview

The core of colloid implementation is in the following two files:
* `src/pebs.h` contains key colloid configuration parameters
* `src/pebs.c` contains implementation of loaded latency measurement infrastructure and colloid migration algorithm

The fork contains the following additional minor updates over vanilla HeMem to enable it work on our setup:
* Updated PEBS counter to use remote NUMA node as alternate tier instead of NVM
* Handling non-contiguous CPU core ids within a socket in `perf_setup` of `src/pebs.c`
* Backport of Icelake PEBS support to HeMem linux kernel in `linux/`: HeMem requires a patched version of linux kernel 5.1.0. This kernel does not include PEBS support for Intel Icelake and newer architectures. To that end, we backported Icelake PEBS support from a newer kernel to the HeMem linux kernel

### Building HeMem + colloid

The following instructions assume a dual-socket server (Intel Ice Lake architecture) where one of the NUMA nodes is used as the default tier, and the other is used as the alternate tier. We have tested the following on Ubuntu 20.04.

#### Requirements

1. We recommend using gcc version 8.4.0 (We ran into issues while compiling HeMem and requirements with later versions of GCC). This can be installed using:
   
```
sudo apt install gcc-8
```
and select the version using:
```
sudo update-alternatives --config gcc
```

2. Install ndctl utility

```
sudo apt install ndctl
```

3. Install prerequisites for compiling linux kernel:

```
sudo apt install build-essential libncurses-dev bison flex libssl-dev libelf-dev fakeroot
sudo apt install dwarves
```

#### Setup

HeMem requires setting up `/dev/dax` files representing each of the tiers. This requires reserving blocks of physical memory at boot time.   

You may set up HeMem to run on your own machine provided you have Intel Optane NVM. HeMem uses `/dev/dax` files to represent DRAM and NVM. Some additional setup is required for setting up the DRAM and NVM `/dev/dax` files to run HeMem.

To set up the `/dev/dax` file representing DRAM, follow the instructions [here](https://pmem.io/2016/02/22/pm-emulation.html "here") in order to reserve a block of DRAM at machine startup to represent the DRAM `/dev/dax` file. HeMem reserves its 140GB of DRAM in this way (enough for its 128GB of reserved DRAM plus some metadata needed for `ndctl`). If your machine has multiple NUMA nodes, ensure that the block of DRAM you reserve is located on the same NUMA node that has NVM. **Do not follow the last set of instructions from pmem.io on setting up a file system on the reserved DRAM.** Instead, set up a `/dev/dax` file to represent it:

1. First, determine the name of the namespace representing the reserved DRAM:

`ndctl list --human`

2. You should see your reserved DRAM. If multiple namespaces are listed, some represent NVM namespaces (described below). You should be able to differentiate the DRAM namespace based on size. Your DRAM namespace is likely in `fsdax` mode. Change the namespace over to `devdax` mode using the following command (in this example, the DRAM namespace is called `namespace0.0`):

`sudo ndctl create-namespace -f -e namespace0.0 --mode=devdax --align 2M`

3. Make note of the `chardev` name of the DRAM `/dev/dax` file. This will be used to tell HeMem which `/dev/dax` file represents DRAM. If this is different from `dax0.0`, then you will need to set the environment variable `DRAMPATH` to your actual DRAM `/dev/dax` file.

To set up the `/dev/dax` file representing NVM, ensure that your machine has NVM in App Direct mode. If you do not already have namespaces representing NVM, then you will need to create them. Follow these steps:

1. List the regions available on your machine:

`ndctl list --regions --human`

2. Note which regions represent NVM. You can differentiate them from the reserved DRAM region based on size or via the `persistence_domain` field, which, for NVM, will read `memory_controller`. Pick the region that is on the same NUMA node as your reserved DRAM. In this example, this is "region1". Create a namespace over this region:

`ndctl create-namespace --region=1 --mode=devdax`

3. Make note of the `chardev` name of the NVM `/dev/dax` file. This will be used to tell HeMem which `/dev/dax` file represents NVM. If this is different from `dax1.0`, then you will need to set the environment variable `NVMPATH` to your actual DRAM `/dev/dax` file.


#### Building

To build HeMem, you must first build the linux kernel HeMem depends on. Build, install, and run the kernel located in the `linux/` directory.

Next, HeMem depends on Hoard. Follow the instructions to build the Hoard library located in the `Hoard/` directory.

HeMem also depends on libsyscall_intercept to intercept memory allocation system calls. Follow the instructions to build and install libsyscall_intercept [here](https://github.com/pmem/syscall_intercept).

Once the proper kernel version is running, the `/dev/dax` files have been set up, and all dependencies have been installed, HeMem can be built with the supplied Makefile by typing `make` from the `src/` directory.

#### Running

You will likely need to add the paths to the build HeMem library and the Hoard library to your LD_LIBRARY_PATH variable:

`export LD_LIBRARY_PATH=path/to/hemem/lib:/path/to/Hoard/lib:$LD_LIBRARY_PATH`

You may also need to increase the number of allowed mmap ranges:

`echo 1000000 > /proc/sys/vm/max_map_count`

HeMem requires the user be root in order to run. Applications can either be linked with Hemem or run unmodified via the `LD_PRELOAD` environment variable:

`LD_PRELOAD=/path/to/hemem/lib.so ./foo [args]`

### Microbenchmarks

A Makefile is provided to build the GUPS microbenchmarks.

To reproduce the Uniform GUPS results, run the `run-random.sh` script. Results will be printed to the `random.txt` file. The throughput results shown in the paper are the "GUPS" lines.

To reproduce the Hotset GUPS results, run the `run.sh` script. Results will be printed to the `results.txt` file. The throughput results shown in the paper are the "GUPS" lines.

To reproduce the Instantaneous GUPS results, run the `run-instantaneous.sh` script. Results will be printed to the `tot_gups.txt` file.

### Application Benchmarks

Applications tested with HeMem are located in the `apps/` directory.

#### Silo 

The Silo application can be found in the `apps/silo_hemem/silo` directory.. Run the provided `run_batch.sh` script. Results will be in the `batch/results.txt` file. The reported throughput numbers are numbers in the first column of the file.

#### FlexKVS

The FlexKVS application can be found in the `apps/flexkvs` directory. These results require a separate machine for the clients.

#### GapBS

The GapBS application can be found in the `apps/gapbs` directory. To run the BC algorithm reported in the paper, you may run the following command:

`LD_PRELOAD=/path/to/hemem/lib ./bc -g <scale>`

which will run the bc algorithm with HeMem on a graph with 2^scale vertices.

