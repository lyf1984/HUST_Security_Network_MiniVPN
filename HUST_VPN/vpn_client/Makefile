object = vpn_client.o vpn_client_setup.o
CFLAGS = -lssl -lcrypto -lpthread -w

all: vpn_client clear

vpn_client: $(object)
	gcc -o vpn_client $(object) ${CFLAGS}

%.o : %.c
	gcc -c $< ${CFLAGS}

.PHONY:clear
clear:
	rm *.o

clean:
	rm vpn_client

