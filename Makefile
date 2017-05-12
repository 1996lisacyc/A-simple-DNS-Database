all: server client

server: server.c status.h
	cc -o server server.c -pthread
	
client: client.c status.h
	cc -o client client.c
	
clean:
	rm server client
