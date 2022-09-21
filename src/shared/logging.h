#ifndef HEMEM_LOGGING_H
#define HEMEM_LOGGING_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

extern FILE *hememlogf;
#define LOG(...) fprintf(stderr, __VA_ARGS__)
//#define LOG(...) fprintf(hememlogf, __VA_ARGS__)
//#define LOG(str, ...) while (0) {}

extern FILE *timef;
extern bool timing;

static inline void log_time(const char* fmt, ...)
{
  if (timing) {
    va_list args;
    va_start(args, fmt);
    vfprintf(timef, fmt, args);
    va_end(args);
  }
}

//#define LOG_TIME(str, ...) log_time(str, __VA_ARGS__)
//#define LOG_TIME(str, ...) fprintf(timef, str, __VA_ARGS__)
#define LOG_TIME(str, ...) while (0) {}

#define STATS_THREAD

extern FILE *statsf;
#define LOG_STATS(str, ...) fprintf(stderr, str, __VA_ARGS__)
//#define LOG_STATS(str, ...) fprintf(statsf, str, __VA_ARGS__)
//#define LOG_STATS(str, ...) while (0) {}

void log_init(const char* log_name);

#endif
