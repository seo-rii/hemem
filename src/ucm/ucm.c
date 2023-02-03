#include <signal.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "hemem-ucm.h"
#include "pebs.h"

extern int pfd[PEBS_NPROCS][NPBUFTYPES];

static void sigusr1_handler(int arg)
{
  fprintf(stderr, "SIGUSR1...\n");
  for(int i = 0; i < PEBS_NPROCS; i++) {
    for(int j = 0; j < NPBUFTYPES; j++) {
      if(pfd[i][j] != 0) {
	ioctl(pfd[i][j], PERF_EVENT_IOC_RESET, 0);
	ioctl(pfd[i][j], PERF_EVENT_IOC_ENABLE, 0);
      }
    }
  }
}

int main(int argc, char *argv[])
{
    fprintf(stderr, "hemem_ucm_init...\n");
    hemem_ucm_init();

    fprintf(stderr, "setting up perf...\n");
    pebs_init();
    fprintf(stdout, "ready\n");

    signal(SIGUSR1, sigusr1_handler);

    while (1) {
      sleep(1);	// XXX: Shouldn't we at least be sleeping?
    }
    //pthread_join(&fault_thread, NULL);
    //pthread_join(&request_thread, NULL);
    //fprintf(stdout, "done\n");

    return 0;
}
