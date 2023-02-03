#ifndef HEMEM_TIMER_H
#define HEMEM_TIMER_H

#include <stdint.h>

/* Returns the number of seconds encoded in T, a "struct timeval". */
#define tv_to_double(t) (t.tv_sec + (t.tv_usec / 1000000.0))

static inline uint64_t rdtscp(void)
{
    uint32_t eax, edx;
    // why is "ecx" in clobber list here, anyway? -SG&MH,2017-10-05
    __asm volatile ("rdtscp" : "=a" (eax), "=d" (edx) :: "ecx", "memory");
    return ((uint64_t)edx << 32) | eax;
}

void timeDiff(struct timeval *d, struct timeval *a, struct timeval *b);
double elapsed(struct timeval *starttime, struct timeval *endtime);
long clock_time_elapsed(struct timespec start, struct timespec end);

#endif /* HEMEM_TIMER_H */
