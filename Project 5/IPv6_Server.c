#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <pthread.h>

#define SERVER_TCP_PORT	14786	
#define BUFFER_LEN		256	

void *thread_action(void *data);
int client_number = 0;

int main(int argc, char **argv) {
	int	port_number, sockfd, new_sockfd, client_len;
	struct sockaddr_in6	server_v6, client_v6;
	pthread_t thread[BUFFER_LEN];

	switch (argc) {
	case 1:
		port_number = SERVER_TCP_PORT;
		break;
	case 2:
		port_number = atoi(argv[1]);
		break;
	default:
		fprintf(stderr, "Usage: %s [port]\n", argv[0]);
		exit(1);
	}

	/* Create a stream socket to connect to receive a connection request from IPv6 Clients */
	if ((sockfd = socket(AF_INET6, SOCK_STREAM, 0)) == -1) {
		fprintf(stderr, "ERROR: Cannot create a socket\n");
		exit(1);
	}

	/* Bind an address to the socket */ 
	bzero((char*)&server_v6, sizeof(struct sockaddr_in6));
	server_v6.sin6_family = AF_INET6;
	server_v6.sin6_flowinfo = 0;
	server_v6.sin6_port = htons(port_number);
	server_v6.sin6_addr = in6addr_any;
	if (bind(sockfd, (struct sockaddr*)&server_v6, sizeof(server_v6)) == -1) {
		fprintf(stderr, "ERROR: Cannot bind name to socket\n");
		exit(1);
	}

	/* Queue up to 5 connect requests */
	if (listen(sockfd, 5) == -1) {
		fprintf(stderr, "ERROR: Cannot listen\n");
		exit(1);
	}

	while (1) {
		/* Accept the connection request sent by IPv6 Clients */
		/* Create a new stream socket to connect with IPv6 Clients */
		client_len = sizeof(client_v6);
		if ((new_sockfd = accept(sockfd, (struct sockaddr*)&client_v6, &client_len)) == -1) {
			fprintf(stderr, "ERROR: Cannot accept client\n");
			exit(1);
		}

		/* Keep the number of clients that the IPv6 Server can handle at the same time at 3 or less */
		if (client_number > 3) {
			continue;
		}
		
		/* Implement thread-based concurrent server */
		if (pthread_create(&thread[client_number], NULL, thread_action, (void*)&new_sockfd) == -1) {
			fprintf(stderr, "ERROR: Cannot create Thread\n");
			close(new_sockfd);
			continue;
		}
		client_number++;
	}

	close(new_sockfd);
	close(sockfd);
	return(0);
}

void *thread_action(void *arg) {
	int receive_sockfd = *((int*)arg);
	int transmit_sockfd;
	struct sockaddr_in client_v4;;
	char buffer[BUFFER_LEN];

	while (1) {
		/* Read data sent from IPv6 Clients */
		/* Close the connection as soon as receive the data so that the number of connections does not exceed 3 */
		if (read(receive_sockfd, buffer, sizeof(buffer)) <= 0) {
			close(receive_sockfd);
			client_number--;
			break;
		}

		/* Output the received token */
		printf("%s", buffer);

		/* Create a new stream socket to connect with IPv4 Client */
		if ((transmit_sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
			fprintf(stderr, "ERROR: Cannot create a socket\n");
			exit(1);
		}

		/* Get IPv4 Client's address */
		bzero((char*)&client_v4, sizeof(struct sockaddr_in));
		client_v4.sin_family = AF_INET;
		client_v4.sin_port = htons(20163);
		inet_pton(AF_INET, "127.0.0.1", &client_v4.sin_addr);

		/* Request connection to IPv4 Client */
		if (connect(transmit_sockfd, (struct sockaddr*)&client_v4, sizeof(client_v4)) == -1) {
			fprintf(stderr, "ERROR: Cannot connect\n");
			exit(1);
		}

		/* Write recieved data to IPv4 Client */
		write(transmit_sockfd, buffer, BUFFER_LEN);

		if (strncmp(buffer, "RANDOM5", 7) == 0) {
			break;
		}
	}
	close(transmit_sockfd);
	close(receive_sockfd);
}