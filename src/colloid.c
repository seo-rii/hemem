#define _GNU_SOURCE
#include <stdlib.h>
#include <pthread.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <pthread.h>
#include <assert.h>
#include <sys/time.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <sys/mman.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <math.h>
#include <signal.h>

#include "pebs.h"
#include "hemem.h"
#include "timer.h"
#include "spsc-ring.h"

#define USE_FILTER1
#define CHA_MSR_PMON_BASE 0x0E00L
#define CHA_MSR_PMON_CTL_BASE 0x0E01L
#define CHA_MSR_PMON_FILTER0_BASE 0x0E05L
#define CHA_MSR_PMON_FILTER1_BASE 0x0E06L
#define CHA_MSR_PMON_STATUS_BASE 0x0E07L
#define CHA_MSR_PMON_CTR_BASE 0x0E08L
#define NUM_CHA_BOXES 18 // There are 32 CHA boxes in icelake server. After the first 18 boxes, the couter offsets change.
#define NUM_CHA_COUNTERS 4
#define MSR_OFFSET 0x10 // Offset for cascadelake

uint64_t cur_ctr_tsc[NUM_CHA_BOXES][NUM_CHA_COUNTERS], prev_ctr_tsc[NUM_CHA_BOXES][NUM_CHA_COUNTERS];
uint64_t cur_ctr_val[NUM_CHA_BOXES][NUM_CHA_COUNTERS], prev_ctr_val[NUM_CHA_BOXES][NUM_CHA_COUNTERS];

FILE *colloid_log_f = NULL;
int colloid_msr_fd;

double smoothed_occ_local, occ_local;
double smoothed_occ_remote, occ_remote;
double smoothed_inserts_local, inserts_local;
double smoothed_inserts_remote, inserts_remote;
double p_lo, p_hi;

static inline void sample_cha_ctr(int cha, int ctr) {
    uint32_t msr_num;
    uint64_t msr_val;
    int ret;

    msr_num = CHA_MSR_PMON_CTR_BASE + (MSR_OFFSET * cha) + ctr;
    ret = pread(colloid_msr_fd, &msr_val, sizeof(msr_val), msr_num);
    if (ret != sizeof(msr_val)) {
        perror("ERROR: failed to read MSR");
    }
    prev_ctr_val[cha][ctr] = cur_ctr_val[cha][ctr];
    cur_ctr_val[cha][ctr] = msr_val;
    prev_ctr_tsc[cha][ctr] = cur_ctr_tsc[cha][ctr];
    cur_ctr_tsc[cha][ctr] = rdtscp();
}

void colloid_setup(int cpu) {
  // Open msr file
  char filename[100];
  sprintf(filename, "/dev/cpu/%d/msr", cpu);
  colloid_msr_fd = open(filename, O_RDWR);
  if(colloid_msr_fd == -1) {
    perror("Failed to open msr file");
  }

  // Setup counters
  int cha, ctr, ret;
  uint32_t msr_num;
  uint64_t msr_val;
  for(cha = 0; cha < NUM_CHA_BOXES; cha++) {
	// Icelake offset multiplier is MSR_OFFSET
      msr_num = CHA_MSR_PMON_FILTER0_BASE + (MSR_OFFSET * cha); // Filter0
      msr_val = 0x00000000; // default; no filtering
      ret = pwrite(colloid_msr_fd,&msr_val,sizeof(msr_val),msr_num);
      if (ret != 8) {
	  printf("wrmsr FILTER0 failed for cha: %d\n", cha);
          perror("wrmsr FILTER0 failed");
      }

      #ifdef USE_FILTER1
      msr_num = CHA_MSR_PMON_FILTER1_BASE + (MSR_OFFSET * cha); // Filter1
      msr_val = (cha%2 == 0)?(0x40432):(0x40431); // Filter DRd of local/remote on even/odd CHA boxes
      ret = pwrite(colloid_msr_fd,&msr_val,sizeof(msr_val),msr_num);
      if (ret != 8) {
         perror("wrmsr FILTER1 failed");
      }
      #endif

      msr_num = CHA_MSR_PMON_CTL_BASE + (MSR_OFFSET * cha) + 0; // counter 0
      msr_val = (cha%2==0)?(0x00c8168600400136):(0x00c8170600400136); // TOR Occupancy, DRd, Miss, local/remote on even/odd CHA boxes
      ret = pwrite(colloid_msr_fd,&msr_val,sizeof(msr_val),msr_num);
      if (ret != 8) {
          perror("wrmsr COUNTER0 failed");
      }

      msr_num = CHA_MSR_PMON_CTL_BASE + (MSR_OFFSET * cha) + 1; // counter 1
      msr_val = (cha%2==0)?(0x00c8168600400135):(0x00c8170600400135); // TOR Inserts, DRd, Miss, local/remote on even/odd CHA boxes
      ret = pwrite(colloid_msr_fd,&msr_val,sizeof(msr_val),msr_num);
      if (ret != 8) {
          perror("wrmsr COUNTER1 failed");
      }

      msr_num = CHA_MSR_PMON_CTL_BASE + (MSR_OFFSET * cha) + 2; // counter 2
      msr_val = 0x400000; // CLOCKTICKS
      ret = pwrite(colloid_msr_fd,&msr_val,sizeof(msr_val),msr_num);
      if (ret != 8) {
          perror("wrmsr COUNTER2 failed");
      }
  }

  // Initialize stats
  for(cha = 0; cha < NUM_CHA_BOXES; cha++) {
        for(ctr = 0; ctr < NUM_CHA_COUNTERS; ctr++) {
            cur_ctr_tsc[cha][ctr] = 0;
            cur_ctr_val[cha][ctr] = 0;
            sample_cha_ctr(cha, ctr);
        }
    }

  smoothed_occ_local = 0.0;
  occ_local = 0.0;
  smoothed_occ_remote = 0.0;
  occ_remote = 0.0;
  smoothed_inserts_local = 0.0;
  inserts_local = 0.0;
  smoothed_inserts_remote = 0.0;
  inserts_remote = 0.0;
  p_lo = 0.0;
  p_hi = 1.0;


  colloid_log_f = fopen("/tmp/hemem-colloid.log", "w");
  if(colloid_log_f == NULL) {
    perror("open colloid log file failed");
  }
}

int colloid_printf(const char *format, ...) {
    int ret;
    va_list args;
    
    va_start(args, format);
    ret = vdprintf(colloid_log_f, format, args);
    va_end(args);
    
    return ret;
}

void colloid_log_pre(void) {
    colloid_printf( 
    "occ_local=%lf"
    ",occ_remote=%lf"
    ",inserts_local=%lf"
    ",inserts_remote=%lf"
    ",inst_occ_local=%lf"
    ",inst_occ_remote=%lf"
    ",inst_inserts_local=%lf"
    ",inst_inserts_remote=%lf"
    ",p_lo=%lf"
    ",p_hi=%lf",
    smoothed_occ_local,
    smoothed_occ_remote,
    smoothed_inserts_local,
    smoothed_inserts_remote,
    occ_local,
    occ_remote,
    inserts_local,
    inserts_remote,
    p_lo,
    p_hi);
}

void colloid_log_stat(void) {
  LOG_STATS("\tocc_local: [%lf]\t occ_remote: [%lf]\n", smoothed_occ_local, smoothed_occ_remote);
}

void colloid_update_stats() {
  uint64_t cum_occ, delta_tsc, cum_inserts;
  double cur_occ, cur_rate;
  // Sample counters and update state
  // TODO: For starters using CHA0 for local and CHA1 for remote
  sample_cha_ctr(0, 0); // CHA0 occupancy
  sample_cha_ctr(0, 1); // CHA0 inserts
  sample_cha_ctr(1, 0);
  sample_cha_ctr(1, 1);

  cum_occ = cur_ctr_val[0][0] - prev_ctr_val[0][0];
  delta_tsc = cur_ctr_tsc[0][0] - prev_ctr_tsc[0][0];
  cur_occ = ((double)cum_occ)/((double)delta_tsc);
  occ_local = cur_occ;
  smoothed_occ_local = COLLOID_EWMA*cur_occ + (1-COLLOID_EWMA)*smoothed_occ_local;

  cum_inserts = cur_ctr_val[0][1] - prev_ctr_val[0][1];
  // delta_tsc = cur_ctr_tsc[0][1] - prev_ctr_tsc[0][1];
  // cur_rate = ((double)cum_inserts)/((double)delta_tsc);
  inserts_local = (double)cum_inserts;
  smoothed_inserts_local = COLLOID_EWMA*((double)cum_inserts) + (1-COLLOID_EWMA)*smoothed_inserts_local;

  cum_occ = cur_ctr_val[1][0] - prev_ctr_val[1][0];
  delta_tsc = cur_ctr_tsc[1][0] - prev_ctr_tsc[1][0];
  cur_occ = ((double)cum_occ)/((double)delta_tsc);
  occ_remote = cur_occ;
  smoothed_occ_remote = COLLOID_EWMA*cur_occ + (1-COLLOID_EWMA)*smoothed_occ_remote;

  cum_inserts = cur_ctr_val[1][1] - prev_ctr_val[1][1];
  // delta_tsc = cur_ctr_tsc[1][1] - prev_ctr_tsc[1][1];
  // cur_rate = ((double)cum_inserts)/((double)delta_tsc);
  inserts_remote = (double)cum_inserts;
  smoothed_inserts_remote = COLLOID_EWMA*((double)cum_inserts) + (1-COLLOID_EWMA)*smoothed_inserts_remote;
}

double colloid_target_delta(double beta) {
  double target_delta;
  #ifdef COLLOID_EXPR2
    target_delta = fabs(smoothed_occ_local - beta * smoothed_occ_remote);
    target_delta /= ((1.0+beta)*(smoothed_occ_local+smoothed_occ_remote));
  #elif defined COLLOID_EXPR3
    target_delta = fabs(smoothed_occ_local - beta * smoothed_occ_remote);
    target_delta /= ((smoothed_inserts_local+smoothed_inserts_remote)*(beta*smoothed_occ_remote/smoothed_inserts_remote + smoothed_occ_local/smoothed_inserts_local));
  #elif defined COLLOID_BINSEARCH
    if(fabs(smoothed_occ_local - beta * smoothed_occ_remote) < COLLOID_DELTA*smoothed_occ_local) {
      // We are within target; don't want to migrate anything
      target_delta = 0.0;
    } else {
      cur_p = smoothed_inserts_local/(smoothed_inserts_local+smoothed_inserts_remote);
      if(smoothed_occ_local < beta * smoothed_occ_remote) {
        p_lo = cur_p;
        if(p_hi <= p_lo) {
          // reset p_hi
          p_hi = 1.0;
        }
      } else {
        p_hi = cur_p;
        if(p_lo >= p_hi) {
          // reset p_lo
          p_lo = 0.0;
        }
      }
      if(fabs(p_hi-p_lo) < COLLOID_EPSILON) {
        if(smoothed_occ_local < beta * smoothed_occ_remote) {
          p_hi = 1.0;
        } else {
          p_lo = 0.0;
        } 
      }
      target_delta = fabs((p_lo+p_hi)/2 - cur_p);
    }
  #else
    target_delta = fabs(smoothed_occ_local - beta * smoothed_occ_remote);
    target_delta /= ((smoothed_occ_local+smoothed_occ_remote));
  #endif
  return target_delta;
}

double colloid_beta() {
  double beta;
  #ifdef RATE_BETA
    beta = smoothed_inserts_local/smoothed_inserts_remote;
  #else
    beta = COLLOID_BETA;
  #endif
  return beta;
}