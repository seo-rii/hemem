HEMEMDIR = $(CURDIR)/../src

CC = gcc
CFLAGS = -g -Wall -O3
#CFLAGS = -g3 -Wall -O0
INCLUDES = -I../linux/usr/include -I${HEMEMDIR}/ucm -I${HEMEMDIR}/shared
LIBS = -lm -lpthread -L../Hoard/src -lhoard -L${HEMEMDIR}/
BUILD = ./build

default: ${BUILD} ${BUILD}/gups-sparse-huge ${BUILD}/gups-sparse-base \
	    ${BUILD}/gups-sparse-oracle ${BUILD}/gups-sparse-oracle-base \
		${BUILD}/gups-dense-sparse-huge ${BUILD}/gups-dense-sparse-base ${BUILD}/gups-dense-sparse-oracle \
		${BUILD}/gups-semisparse-huge ${BUILD}/gups-semisparse-oracle

${BUILD}:
	mkdir -p ${BUILD};

${BUILD}/gups-random: ${BUILD}/gups-random.o ${BUILD}/zipf.o ../src/timer.o
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBS) # -L$(HEMEMDIR) -lhemem

${BUILD}/gups-small: ${BUILD}/gups-small.o
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ ../src/timer.o $(LIBS)

${BUILD}/gups: ${BUILD}/gups.o ${BUILD}/zipf.o ../src/timer.o
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBS)

${BUILD}/gups-sparse-huge: ${BUILD}/gups-sparse.o ${BUILD}/zipf.o ../src/timer.o
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBS) -lhemem

${BUILD}/gups-semisparse-huge: ${BUILD}/gups-semisparse.o ${BUILD}/zipf.o ../src/timer.o
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBS) -lhemem

gups-warmset: gups-warmset.o
	$(CC) $(CFLAGS) $(INCLUDES) -o gups-warmset gups-warmset.o zipf.o ../src/timer.o $(LIBS) -L$(HEMEMDIR) -lhemem

gups-hotset-only: gups-hotset-only.o
	$(CC) $(CFLAGS) $(INCLUDES) -o gups-hotset-only gups-hotset-only.o zipf.o ../src/timer.o $(LIBS) -L$(HEMEMDIR) -lhemem

gups-pebs: gups.o
	$(CC) $(CFLAGS) $(INCLUDES) -o gups-pebs gups.o zipf.o ../src/timer.o $(LIBS) -L$(HEMEMDIR) -lhemem

testgups: test.o
	$(CC) $(CFLAGS) $(INCLUDES) -o testgups test.o zipf.o ../src/timer.o $(LIBS) #-L$(HEMEMDIR) -lhemem

gups-hotset-move: gups-hotset-move.o
	$(CC) $(CFLAGS) $(INCLUDES) -o gups-hotset-move gups-hotset-move.o zipf.o $(LIBS) -L$(HEMEMDIR) -lhemem

${BUILD}/gups-semisparse-oracle: ${BUILD}/gups-semisparse-oracle.o ${BUILD}/zipf.o ../src/timer.o
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBS) -L$(HEMEMDIR)

${BUILD}/gups-sparse-base: ${BUILD}/gups-sparse.o ${BUILD}/zipf.o ../src/timer.o
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBS) -lhemem-base

${BUILD}/gups-sparse-oracle: ${BUILD}/gups-sparse-oracle-huge.o ${BUILD}/zipf.o ../src/timer.o
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBS) -L$(HEMEMDIR) -D PAGE_SIZE=2097152UL

${BUILD}/gups-sparse-oracle-base: ${BUILD}/gups-sparse-oracle-base.o ${BUILD}/zipf.o ../src/timer.o
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBS) -L$(HEMEMDIR) -D PAGE_SIZE=4096UL

${BUILD}/gups-dense-sparse-oracle: ${BUILD}/gups-dense-sparse-oracle.o ${BUILD}/zipf.o ../src/timer.o
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBS) -L$(HEMEMDIR)

${BUILD}/gups-dense-sparse-huge: ${BUILD}/gups-dense-sparse.o ${BUILD}/zipf.o ../src/timer.o
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBS) -L$(HEMEMDIR) -lhemem

${BUILD}/gups-dense-sparse-base: ${BUILD}/gups-dense-sparse.o ${BUILD}/zipf.o ../src/timer.o
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBS) -L$(HEMEMDIR) -lhemem-base

${BUILD}/gups-hotset-move: ${BUILD}/gups-hotset-move.o ${BUILD}/zipf.o ../src/timer.o
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBS) -L$(HEMEMDIR) -lhemem

${BUILD}/gups-simple: ${BUILD}/gups.o ${BUILD}/zipf.o ../src/timer.o
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBS) -L$(HEMEMDIR) -lhemem-simple

${BUILD}/gups-lru: ${BUILD}/gups.o ${BUILD}/zipf.o ../src/timer.o
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBS) -L$(HEMEMDIR) -lhemem-lru

${BUILD}/gups-lru-swap: ${BUILD}/gups.o ${BUILD}/zipf.o ../src/timer.o
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBS) -L$(HEMEMDIR) -lhemem-lru-swap

${BUILD}/gups-random.o: gups-random.c zipf.c gups.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ -c  $<

${BUILD}/gups.o: gups.c zipf.c gups.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ -c  $<

${BUILD}/gups-sparse.o: gups-sparse.c zipf.c  gups.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ -c $<

${BUILD}/gups-semisparse.o: gups-semisparse.c zipf.c  gups.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ -c $<

${BUILD}/gups-semisparse-oracle.o: gups-semisparse-oracle.c  gups.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ -c  $<

${BUILD}/gups-sparse-oracle-base.o: gups-sparse-oracle.c gups.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ -c  $< -D PAGE_SIZE=4096UL

${BUILD}/gups-sparse-oracle-huge.o: gups-sparse-oracle.c  gups.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ -c  $< -D PAGE_SIZE=2097152UL

${BUILD}/gups-dense-sparse-oracle.o: gups-dense-sparse-oracle.c gups.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ -c $<

${BUILD}/gups-dense-sparse.o: gups-dense-sparse.c zipf.c  gups.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ -c $<

${BUILD}/gups-hotset-move.o: gups-hotset-move.c zipf.c gups.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ -c $<

 ${BUILD}/zipf.o: zipf.c 
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ -c $<

gups-warmset.o: gups-warmset.c zipf.c gups.h
	$(CC) $(CFLAGS) $(INCLUDES) -c gups-warmset.c zipf.c

gups-hotset-only.o: gups-hotset-only.c zipf.c gups.h
	$(CC) $(CFLAGS) $(INCLUDES) -c gups-hotset-only.c zipf.c

test.o: test.c zipf.c  gups.h
	$(CC) $(CFLAGS) $(INCLUDES) -c test.c zipf.c

clean:
	$(RM) ${BUILD}/*
