#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <pthread.h>

#define SERVER_TCP_PORT	50000
#define BUFFER_LEN 256

int main(int argc, char **argv) {
	int n, sockfd, new_sockfd, port_number;
	int client_len, new_sd;
	struct hostent *server, *client;
	struct sockaddr_in server_v4, client_v4;
	char buffer_1[BUFFER_LEN], buffer_2[BUFFER_LEN];

	switch (argc) {
	case 2:
		port_number = SERVER_TCP_PORT;
		break;
	case 3:
		port_number = atoi(argv[2]);
		break;
	default:
		fprintf(stderr, "Usage: %s host [port]\n", argv[0]);
		exit(1);
	}

	/* Create a stream socket to connect with IPv4 Server */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		fprintf(stderr, "ERROR: Cannot create a socket\n");
		exit(1);
	}

	/* Get IPv4 Server's address */
	if ((server = gethostbyname(argv[1])) == NULL) {
		fprintf(stderr, "ERROR: Cannot get server's address\n");
		exit(1);
	}
	bzero((char*)&server_v4, sizeof(struct sockaddr_in));
	server_v4.sin_family = AF_INET;
	server_v4.sin_port = htons(port_number);
	bcopy(server->h_addr, (char*)&server_v4.sin_addr, server->h_length);

	/* Request connection to IPv4 Server */
	if (connect(sockfd, (struct sockaddr*)&server_v4, sizeof(server_v4)) == -1) {
		fprintf(stderr, "ERROR: Cannot connect\n");
		exit(1);
	}

	/* Create a new stream socket to receive a connection request from IPv6 Server */
	if ((new_sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		fprintf(stderr, "ERROR: Cannot create a socket\n");
		exit(1);
	}

	/* Bind an address to the new stream socket */
	bzero((char*)&server, sizeof(struct sockaddr_in));
	client_v4.sin_family = AF_INET;
	client_v4.sin_port = htons(20163);
	client_v4.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(new_sockfd, (struct sockaddr*)&client_v4, sizeof(client_v4)) == -1) {
		fprintf(stderr, "ERROR: Cannot bind name to socket\n");
		exit(1);
	}

	/* Queue up to 5 connect requests */
	listen(new_sockfd, 5);

	/* Communicate between IPv4 Server and IPv4 Client */
	while (n = read(sockfd, buffer_1, sizeof(buffer_1)) > 0) {
		printf("%s", buffer_1);
		memset(buffer_1, 0x00, sizeof(buffer_1));

		read(sockfd, buffer_1, sizeof(buffer_1));
		printf("%s", buffer_1);
		memset(buffer_1, 0x00, sizeof(buffer_1));

		read(0, buffer_1, sizeof(buffer_1));
		write(sockfd, buffer_1, strlen(buffer_1));
		if (strncmp(buffer_1, "OK", 2) == 0) {
			memset(buffer_1, 0x00, sizeof(buffer_1));
			break;
		}
		memset(buffer_1, 0x00, sizeof(buffer_1));
	}


	memset(buffer_2, 0x00, sizeof(buffer_2));
	while (1) {
		/* Accept the connection request sent by IPv6 Server */
		/* Create a new stream socket to connect with IPv6 Server */
		if ((new_sd = accept(new_sockfd, (struct sockaddr*)&client, &client_len)) == -1) {
			fprintf(stderr, "ERROR: Cannot accept client\n");
			exit(1);
		}

		/* Read data sent from IPv6 Server */
		if (read(new_sd, buffer_2, sizeof(buffer_2)) <= 0) {
			close(new_sd);
			break;
		}

		/* Write recieved data to IPv4 Server */
		if (strncmp(buffer_2, "RANDOM5", 7) == 0) {
			write(sockfd, buffer_2, 28);
			write(sockfd, "\n", 1);
			break;
		}
		write(sockfd, buffer_2, 28);
		write(sockfd, ",", 1);
		close(new_sd);
	}

	/* Receive a success message from IPv4 Server */
	while (n = read(sockfd, buffer_1, sizeof(buffer_1)) > 0) {
		printf("%s", buffer_1);
		memset(buffer_1, 0x00, sizeof(buffer_1));

		read(sockfd, buffer_1, sizeof(buffer_1));
		printf("%s", buffer_1);
	}

	close(sockfd);
	return(0);
}