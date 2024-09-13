CC=gcc
CFLAGS=-W -Wall -g

loraw: loraw.c fuse_kernel.h
	$(CC) $(CFLAGS) loraw.c -o loraw -luring
