CC = gcc
CFLAGS = -Wall -I. -pthread

# Default target builds everything
all: libksocket.a initksocket user1 user2

# Makefile target to generate libksocket.a
libksocket.a: ksocket.o
	ar rcs libksocket.a ksocket.o

ksocket.o: ksocket.c ksocket.h
	$(CC) $(CFLAGS) -c ksocket.c

# Makefile target to create the executable to run initksocket.c
initksocket: initksocket.c libksocket.a
	$(CC) $(CFLAGS) -o initksocket initksocket.c -L. -lksocket

# Makefile targets to create the two executable files for user1.c and user2.c
user1: user1.c libksocket.a
	$(CC) $(CFLAGS) -o user1 user1.c -L. -lksocket

user2: user2.c libksocket.a
	$(CC) $(CFLAGS) -o user2 user2.c -L. -lksocket

clean:
	rm -f *.o *.a initksocket user1 user2 output.txt