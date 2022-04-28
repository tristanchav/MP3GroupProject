CC := gcc
LDFLAGS :=  `sdl2-config --cflags --libs` -lssl -lcrypto -lcrypt -lsqlite3 -lSDL2_mixer
UNAME := $(shell uname)
CERT := openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem
SERVER := cd serverdata

ifeq ($(UNAME), Darwin)
CFLAGS := -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib
endif

all: cert client server

cert:
	$(SERVER); $(CERT)

client: clientdata/client.o
	$(CC) $(CFLAGS) -o clientdata/client clientdata/client.o $(LDFLAGS)

client.o: clientdata/client.c
	$(CC) $(CFLAGS) -c clientdata/client.c

server: serverdata/server.o
	$(CC) $(CFLAGS) -o serverdata/server serverdata/server.o $(LDFLAGS)

server.o: serverdata/server.c
	$(CC) $(CFLAGS) -c serverdata/server.c

clean:
	rm -f serverdata/server serverdata/server.o serverdata/cert.pem serverdata/key.pem clientdata/client clientdata/client.o
