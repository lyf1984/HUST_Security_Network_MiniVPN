object = vpn_server.o vpn_server_setup.o vpn_server_session.o
CFLAGS = -lssl -lcrypto -lpthread -lcrypt -w

all: vpn_server clear

vpn_server: $(object)
	gcc -o vpn_server $(object) ${CFLAGS}

%.o : %.c
	gcc -c $< ${CFLAGS}

.PHONY:clear
clear:
	rm *.o

clean:
	rm vpn_server

