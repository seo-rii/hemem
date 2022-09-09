#include "hemem-ucm.h"

int main(int argc, char *argv[])
{
    fprintf(stdout, "hemem_ucm_init...\n");
    hemem_ucm_init();

    fprintf(stdout, "setting up perf...\n");
    paging_init();
    fprintf(stdout, "ready\n");
    while (1) {
        ;
    }
    //pthread_join(&fault_thread, NULL);
    //pthread_join(&request_thread, NULL);
    //fprintf(stdout, "done\n");

    return 0;
}
