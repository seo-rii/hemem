#include "hemem-ucm.h"
#include "pebs.h"

int main(int argc, char *argv[])
{
    fprintf(stderr, "hemem_ucm_init...\n");
    hemem_ucm_init();

    fprintf(stderr, "setting up perf...\n");
    pebs_init();
    fprintf(stderr, "ready\n");
    while (1) {
        ;
    }
    //pthread_join(&fault_thread, NULL);
    //pthread_join(&request_thread, NULL);
    //fprintf(stdout, "done\n");

    return 0;
}
