CC = gcc
CFLAGS = -g

default: all
all: ucm user_app

ucm: ucm.o shared.o
	$(CC) $(LDFLAGS) -o ucm ucm.o shared.o

user_app: user_app.o shared.o
	$(CC) $(LDFLAGS) -o user_app user_app.o shared.o

ucm.o: ucm.c shared.h compiler.h bug.h
	$(CC) $(CFLAGS) -o ucm.o -c ucm.c

user_app.o: user_app.c shared.h compiler.h bug.h
	$(CC) $(CFLAGS) -o user_app.o -c user_app.c

shared.o: shared.c shared.h compiler.h bug.h
	$(CC) $(CFLAGS) -o shared.o -c shared.c

clean:
	${RM} ucm user_app *.o *.sock

