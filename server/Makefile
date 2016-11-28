CC = gcc
CFLAGS = -Wall
LIBS = -lpthread
 
OBJ = server.o


%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

server: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

clean:
	rm -f *.o server
