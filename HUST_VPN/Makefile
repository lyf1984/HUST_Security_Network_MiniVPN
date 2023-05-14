CLIENT = ./vpn_client
SERVER = ./vpn_server
all:
	cd ${CLIENT} && ${MAKE}
	cd ${SERVER} && ${MAKE}
	sudo docker cp vpn_client HostU:/
	sudo docker cp vpn_client HostW:/
