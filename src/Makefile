CC = gcc
APP_CFLAGS = -Wall -O3 -fPIC
UCM_CFLAGS = -Wall -O3
SHARED_CFLAGS = -Wall -O3
#CFLAGS = -g3 -Wall -O0 -fPIC
UCM = ucm
APP = app
SHARED = shared
LDFLAGS = -shared
APP_INCLUDES := -I ../linux/usr/include/
APP_INCLUDES += -I $(SHARED)/
UCM_INCLUDES := -I ../linux/usr/include/
UCM_INCLUDES += -I ../linux/include/uapi
UCM_INCLUDES += -I $(SHARED)/
SHARED_INCLUDES := -I $(SHARED)/
LIBS = -lm -lpthread
#HEMEM_LIBS = $(LIBS) -ldl -lsyscall_intercept -L../Hoard/src -lhoard
HEMEM_LIBS = $(LIBS) -ldl -lsyscall_intercept

default: all
all:app central-manager
app: libhemem.so

libhemem.so: hemem-app.o  interpose.o channel-shared-app.o channel-app.o logging-app.o
	$(CC) $(LDFLAGS) -o libhemem.so hemem-app.o interpose.o channel-shared-app.o channel-app.o logging-app.o  $(HEMEM_LIBS)

hemem-app.o: ${APP}/hemem-app.c
	$(CC) $(APP_CFLAGS) $(APP_INCLUDES) -D ALLOC_HEMEM -c ${APP}/hemem-app.c -o hemem-app.o

interpose.o: ${APP}/interpose.c
	$(CC) $(APP_CFLAGS) $(APP_INCLUDES) -c ${APP}/interpose.c

channel-app.o: ${APP}/channel-app.c
	$(CC) $(APP_CFLAGS) $(APP_INCLUDES) -c ${APP}/channel-app.c

central-manager: ucm.o channel-shared.o channel-ucm.o timer.o pebs.o hemem-ucm.o fifo.o spsc-ring.o logging.o
	$(CC) -o central-manager ucm.o channel-shared.o channel-ucm.o timer.o pebs.o hemem-ucm.o fifo.o spsc-ring.o logging.o -lpthread

ucm.o: ${UCM}/ucm.c
	$(CC) $(UCM_CFLAGS) $(UCM_INCLUDES) -c ${UCM}/ucm.c

hemem-ucm.o: ${UCM}/hemem-ucm.c
	$(CC) $(UCM_CFLAGS) $(UCM_INCLUDES) -c ${UCM}/hemem-ucm.c -lpthread
	
channel-shared-app.o: ${SHARED}/channel-shared.c
	$(CC) $(APP_CFLAGS) $(SHARED_INCLUDES) -o channel-shared-app.o  -c ${SHARED}/channel-shared.c

channel-shared.o: ${SHARED}/channel-shared.c
	$(CC) $(SHARED_CFLAGS) $(SHARED_INCLUDES) -c ${SHARED}/channel-shared.c

channel-ucm.o: ${UCM}/channel-ucm.c
	$(CC) $(UCM_CFLAGS) $(UCM_INCLUDES) -c ${UCM}/channel-ucm.c

timer.o: ${UCM}/timer.c
	$(CC) $(UCM_CFLAGS) $(UCM_INCLUDES) -c ${UCM}/timer.c

pebs.o: ${UCM}/pebs.c
	$(CC) $(UCM_CFLAGS) $(UCM_INCLUDES) -c ${UCM}/pebs.c -lpthread

fifo.o: ${UCM}/fifo.c
	$(CC) $(UCM_CFLAGS) $(UCM_INCLUDES) -c ${UCM}/fifo.c

spsc-ring.o: ${UCM}/spsc-ring.c
	$(CC) $(UCM_CFLAGS) $(UCM_INCLUDES) -c ${UCM}/spsc-ring.c

logging.o: ${SHARED}/logging.c
	$(CC) $(SHARED_CFLAGS) $(SHARED_INCLUDES) -c ${SHARED}/logging.c

logging-app.o: ${SHARED}/logging.c
	$(CC) $(APP_CFLAGS) $(SHARED_INCLUDES) -o logging-app.o -c $(SHARED)/logging.c

clean:
	$(RM) *.o *.so central-manager
