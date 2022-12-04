#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>

#include "logging.h"

FILE* hememlogf;

FILE* timef;
bool timing = false;

FILE* statsf;

void log_init(const char* logname)
{
  char logbuffer[64];
  snprintf(logbuffer, 64, "/tmp/log_%s.txt", logname);
  hememlogf = fopen(logbuffer, "w+");
  if (hememlogf == NULL) {
    perror("log file open");
    assert(0);
  }

  char timebuffer[64];
  snprintf(timebuffer, 64, "/tmp/times_%s.txt", logname);
  timef = fopen(timebuffer, "w+");
  if (timef == NULL) {
    perror("time file open");
    assert(0);
  }

  char statsbuffer[64];
  snprintf(statsbuffer, 64, "/tmp/sats_%s.txt", logname);
  statsf = fopen(statsbuffer, "w+");
  if (statsf == NULL) {
    perror("stats file open");
    assert(0);
  }
}
