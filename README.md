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

The following instructions assume a dual-socket server (Intel Ice Lake architecture) where one of the NUMA nodes is used as the default tier, and the other is used as the alternate tier. In the remainder of this document, we are going to assume NUMA 1 is the default tier, and NUMA 0 is the alternate tier (easily interchangeable). We have tested the following on Ubuntu 20.04.

#### Requirements

We recommend using gcc version 8.4.0 (We ran into issues while compiling HeMem and requirements with later versions of GCC). This can be installed using:
   
```
sudo apt install gcc-8
```
and select the version using:
```
sudo update-alternatives --config gcc
```

Next, install ndctl utility

```
sudo apt install ndctl
```

Also, install prerequisites for compiling linux kernel:

```
sudo apt install build-essential libncurses-dev bison flex libssl-dev libelf-dev fakeroot
sudo apt install dwarves
```

#### Setup

HeMem requires setting up `/dev/dax` files representing each of the tiers. This requires reserving blocks of physical memory at boot time.

First, determine the how physical addresses ranges map to NUMA nodes using:

```
dmesg | grep -i "acpi: srat"
```

Next, reserve memory regions of the required size for each of the tiers using the memmap boot command line parameter (see https://docs.pmem.io/persistent-memory/getting-started-guide/creating-development-environments/linux-environments/linux-memmap for details). For example, on our setup, we use the following to reserve 32GB starting at address 130G (corresponding to NUMA1 which we are going to use as default tier), and 96GB starting at address 4G (corresponding to NUMA0 which we are going to use as the alternate tier):

```
GRUB_CMDLINE_LINUX="memmap=32G!130G memmap=96G!4G"
```

After rebooting the system, you can verify whether the regions were reserved using (the two regions should show up as separate namespaces):

```
sudo ndctl list
```

Then, you can setup the `/dev/dax` files using (make sure to use the correct namespace names from above):

```
sudo ndctl create-namespace -f -e namespace0.0 --mode=devdax --align 2M
sudo ndctl create-namespace -f -e namespace1.0 --mode=devdax --align 2M
```
Make note of the "chardevs" in the output for each of the namespaces (e.g., dax1.0, dax0.0).

#### Configuration

Based on your setup, the following configuration parameters may need to be updated:
* Update `DRAMPATH_DEFAULT` and `NVMPATH_DEFAULT` to match the chardevs (from above) for the default tier and alternate tiers respectively
* Update `DRAMSIZE_DEFAULT` and `NVMSIZE_DEFAULT` to the desired capacities of the default tier and alternate respectively
* Update `PEBS_NPROCS` to the number of cores per-socket (can be obtained via `lscpu`)
* Configure which CPU cores to pin HeMem threads to. Update `scanning_thread_cpu` and `migration_thread_cpu` in `src/pebs.c` and `fault_thread_cpu` in `src/hemem.c` accordingly. It is recommended to use dedicated CPU cores for each of the scanning and migration threads
* Update `pebs_core_list` in `src/pebs.c` to the list of CPU cores in the (default tier) socket (use `lscpu` if in doubt)
* Update `LOCAL_NUMA` in `src/pebs.c` to the NUMA node number of the default tier NUMA node   

#### Building

Building HeMem + colloid uses the same procedure as vanilla HeMem. In particular:

First build the linux kernel HeMem depends on. Build, install, and run the kernel located in the `linux/` directory.

Next, HeMem depends on Hoard. Follow the instructions to build the Hoard library located in the `Hoard/` directory.

HeMem also depends on libsyscall_intercept to intercept memory allocation system calls. Follow the instructions to build and install libsyscall_intercept [here](https://github.com/pmem/syscall_intercept).

Once the proper kernel version is running, the `/dev/dax` files have been set up, and all dependencies have been installed, HeMem (+ colloid) can be built with the supplied Makefile by typing `make` from the `src/` directory.

### Running HeMem + colloid

Procedure for running HeMem + colloid is the same as that for vanilla HeMem.

To be safe, increase the number of allowed mmap ranges:

`echo 1000000 | sudo tee /proc/sys/vm/max_map_count`

HeMem requires the user be root in order to run. Applications can be run unmodified via the `LD_PRELOAD` environment variable:

`sudo LD_LIBRARY_PATH=/home/midhul/hemem/src:/home/midhul/hemem/Hoard/src LD_PRELOAD=/home/midhul/hemem/src/libhemem.so <command to run app>`

**Note about potential PEBS issue:** PEBS can sometimes abruptly stop producing samples on certain CPU cores causing HeMem's access monitoring mechanism to become ineffective. To mitigate such issues, it is useful to run `sudo ./run_perf.sh`, which periodically resets PEBS counters, in the background while running HeMem (make sure to update the list of CPU core in the script based on your setup).

