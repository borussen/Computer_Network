#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

// #include <WinSock2.h>   
// #pragma comment(lib,"ws2_32")

int TCP = 0;
int UDP = 0;

typedef struct _Pcap_File_Header {
	unsigned int magic;
	unsigned short major;
	unsigned short minor;
	unsigned int timezone;
	unsigned timestamp;
	unsigned snap_len;
	unsigned linktype;
}PFHeader;

typedef struct _Packet_Header {
	unsigned int sec;
	unsigned int usec;
	unsigned int capture_len;
	unsigned int packet_len;
}PHeader;

typedef struct _Ethernet_Header {
	unsigned char dst_mac[6];
	unsigned char src_mac[6];
	unsigned short type;
}Ethernet_Header;

typedef struct _IP_Header {
	unsigned char header_len : 4;
	unsigned char version : 4;
	unsigned char service_type;
	unsigned short total_len;
	unsigned short identification;
	unsigned short fragmentation;
	unsigned char time_to_live;
	unsigned char protocol;
	unsigned short header_checksum;
	unsigned int src_addr;
	unsigned int dst_addr;
}IP_Header;

typedef struct _TCP_Header {
	unsigned short source_port;
	unsigned short destination_port;
	unsigned int sequence_number;
	unsigned int acknowledgment_number;
	unsigned char reserved_1 : 4;
	unsigned char header_len : 4;
	unsigned char fin : 1;
	unsigned char syn : 1;
	unsigned char rst : 1;
	unsigned char psh : 1;
	unsigned char ack : 1;
	unsigned char urg : 1;
	unsigned char reserved_2 : 2;
	unsigned short window_size;
	unsigned short checksum;
	unsigned short urgent_pointer;
}TCP_Header;

typedef struct _TCP_Option {
	unsigned char type;
}TCP_Option;

typedef struct _UDP_Header {
	unsigned short source_port;
	unsigned short destination_port;
	unsigned short total_length;
	unsigned short checksum;
}UDP_Header;

int parsePacket(FILE* fp);
void parseEthernet(char* buffer);
void viewMAC(unsigned char* mac);
void parseIP(char* buffer);
void parseTCP(char* buffer, int size);
void parseUDP(char* buffer);

int main() {
	char fname[300] = "";
	FILE* fp = 0;

	printf("Enter the file name(.pcap): ");
	scanf("%s", fname);

	fp = fopen(fname, "rb");

	if (fp == NULL) {
		perror("Error! (Wrong file name)\n");
		return 0;
	}

	parsePacket(fp);
	fclose(fp);

	printf("==========================================================================================\n\n");
	printf("The greatest payload sizes among segments in TCP :%d bytes\n", TCP);
	printf("The greatest payload sizes among segments in UDP :%d bytes\n\n", UDP);
	printf("==========================================================================================\n\n");

	return 0;
}

int parsePacket(FILE* fp) {
	char buffer[65536];
	int count = 0;

	PFHeader pfh;
	fread(&pfh, sizeof(pfh), 1, fp);

	PHeader pheader[3001];
	PHeader* ph = pheader;

	while ((feof(fp) == 0) && (fread(ph, sizeof(PHeader), 1, fp) == 1)) {

		count++;
		if (count == 3000) {
			break;
		}

		time_t time = ph->sec;
		struct tm* t;
		t = (struct tm*)localtime(&time);

		printf("==========================================================================================\n");
		printf("\n[Frame %d] Local time - %02d:%02d:%02d.%06d\n", count, t->tm_hour, t->tm_min, t->tm_sec, ph->usec);
		printf("%u bytes on wire (%u bits), %u bytes captured (%u bits)\n", ph->packet_len, 8 * (ph->packet_len), ph->capture_len, 8 * (ph->capture_len));

		fread(buffer, 1, ph->capture_len, fp);
		parseEthernet(buffer);
		ph++;
		printf("\n");
	}

	return 0;
}

void parseEthernet(char* buffer) {
	Ethernet_Header* eh = (Ethernet_Header*)buffer;;

	if (ntohs(eh->type) == 0x0800) {
		parseIP(buffer + sizeof(Ethernet_Header));
	}
	else if (ntohs(eh->type) == 0x0806) {
		printf("ARP : 0x0806\n");
	}
	else {
		printf("Not support\n");
	}
}

void parseIP(char* buffer) {
	IP_Header* ih = (IP_Header*)buffer;

	printf("Total Length: %d bytes / ", ntohs(ih->total_len));
	printf("IP Header Length: %d bytes (%d)\n\n", ih->header_len * 4, ih->header_len);

	if (ih->protocol == 1) {
		printf("Protocol: ICMP (%d)\n", ih->protocol);
	}
	else if (ih->protocol == 6) {
		printf("Protocol: TCP (%d)\n", ih->protocol);
		parseTCP(buffer + (ih->header_len * 4), ntohs(ih->total_len) - (ih->header_len * 4));
	}
	else if (ih->protocol == 17) {
		printf("Protocol: UDP (%d)\n", ih->protocol);
		parseUDP(buffer + (ih->header_len * 4));
	}
	else {
		printf("Protocol Number: %d\n", ih->protocol);
	}
}

void parseTCP(char* buffer, int size) {
	TCP_Header* th = (TCP_Header*)buffer;

	printf("Source Port: %u\n", ntohs(th->source_port));
	printf("Destination Port: %u\n", ntohs(th->destination_port));
	printf("Sequence Number (raw): %u\n", ntohl(th->sequence_number));
	
	if (size - th->header_len * 4 > 0) {
		if (ntohl(th->sequence_number) + size - (th->header_len * 4) - 1 > 4294967295) {
			printf("(Starting sequence number: %u / Ending Sequence number: %lu)\n", ntohl(th->sequence_number), ntohl(th->sequence_number) + size - (th->header_len * 4) - 4294967296);
		}
		else {
			printf("(Starting sequence number: %u / Ending Sequence number: %u)\n", ntohl(th->sequence_number), ntohl(th->sequence_number) + size - (th->header_len * 4) - 1);
		}	
	}

	printf("Acknowledgment Number (raw): %u\n", ntohl(th->acknowledgment_number));

	printf("Flags: ");
	if (th->urg) { printf("URG "); }
	if (th->psh) { printf("PSH "); }
	if (th->rst) { printf("RST "); }
	if (th->fin) { printf("FIN "); }
	if (th->ack) { printf("ACK "); }
	if (th->syn) { printf("SYN "); }
	printf("\n");

	printf("Window: %u\n", ntohs(th->window_size));
	printf("Urgent Pointer: %u\n", ntohs(th->urgent_pointer));

	if (th->header_len * 4 > 20) {
		int option_len = th->header_len * 4 - 20;
		char* buf = buffer + 20;

		printf("Options: (%u bytes)", th->header_len * 4 - 20);
		
		while (option_len > 0) {
			printf(",");
			TCP_Option* to = (TCP_Option*)buf;

			if (to->type == 0) { 
				printf(" End of Option (EOL)");
				option_len = 0;
			}
			else if (to->type == 1) {
				printf(" No-Operation (NOP)");
				option_len -= 1;
				buf += 1;
			}
			else if (to->type == 2) {
				printf(" Maximum segment size (MSS)");
				option_len -= 4;
				buf += 4;
			}
			else if (to->type == 3) {
				printf(" Window scale (WSCALE)");
				option_len -= 3;
				buf += 3;
			}
			else if (to->type == 4) {
				printf(" SACK permitted");
				option_len -= 2;
				buf += 2;
			}
			else if (to->type == 5) {
				printf(" SACK");
				option_len = 0;
			}
			else if (to->type == 8) {
				printf(" Time stamp");
				option_len -= 10;
				buf += 10;
			}
			else if (to->type == 28) {
				printf(" User Timeout (UTO)");
				option_len -= 4;
				buf += 4;
			}
			else {
				printf(" Undefined Options exist..");
				option_len = 0;
			}
		}
		printf("\n");
	}

	if (size - th->header_len * 4 == 1) {
		printf("TCP payload (%u byte)\n", size - th->header_len * 4);
	}
	else {
		printf("TCP payload (%u bytes)\n", size - th->header_len * 4);
	}

	if ((ntohs(th->source_port) == 20) || (ntohs(th->destination_port) == 20)) {
		printf("Application type: FTP\n");
	}
	else if ((ntohs(th->source_port) == 21) || (ntohs(th->destination_port) == 21)) {
		printf("Application type: FTP\n");
	}
	else if ((ntohs(th->source_port) == 22) || (ntohs(th->destination_port) == 22)) {
		printf("Application type: SSH\n");
	}
	else if ((ntohs(th->source_port) == 23) || (ntohs(th->destination_port) == 23)) {
		printf("Application type: TELNET\n");
	}
	else if ((ntohs(th->source_port) == 25) || (ntohs(th->destination_port) == 25)) {
		printf("Application type: SMTP\n");
	}
	else if ((ntohs(th->source_port) == 53) || (ntohs(th->destination_port) == 53)) {
		printf("Application type: DNS\n");
	}
	else if ((ntohs(th->source_port) == 80) || (ntohs(th->destination_port) == 80)) {
		printf("Application type: HTTP\n");
	}
	else if ((ntohs(th->source_port) == 109) || (ntohs(th->destination_port) == 109)) {
		printf("Application type: POP2\n");
	}
	else if ((ntohs(th->source_port) == 110) || (ntohs(th->destination_port) == 110)) {
		printf("Application type: POP3\n");
	}
	else if ((ntohs(th->source_port) == 111) || (ntohs(th->destination_port) == 111)) {
		printf("Application type: RPC\n");
	}
	else if ((ntohs(th->source_port) == 143) || (ntohs(th->destination_port) == 143)) {
		printf("Application type: IMAP4\n");
	}
	else if ((ntohs(th->source_port) == 179) || (ntohs(th->destination_port) == 179)) {
		printf("Application type: BGP\n");
	}
	else if ((ntohs(th->source_port) == 194) || (ntohs(th->destination_port) == 194)) {
		printf("Application type: IRC\n");
	}
	else if ((ntohs(th->source_port) == 220) || (ntohs(th->destination_port) == 220)) {
		printf("Application type: IMAP3\n");
	}
	else if ((ntohs(th->source_port) == 443) || (ntohs(th->destination_port) == 443)) {
		printf("Application type: HTTPS\n");
	}

	if (TCP < size - th->header_len * 4) {
		TCP = size - th->header_len * 4;
	}
}

void parseUDP(char* buffer) {
	UDP_Header* uh = (UDP_Header*)buffer;

	printf("Source Port: %u\n", ntohs(uh->source_port));
	printf("Destination Port: %u\n", ntohs(uh->destination_port));

	if (ntohs(uh->total_length) - 8 == 1) {
		printf("UDP payload (%u byte)\n", ntohs(uh->total_length) - 8);
	}
	else {
		printf("UDP payload (%u bytes)\n", ntohs(uh->total_length) - 8);
	}

	if ((ntohs(uh->source_port) == 53) || (ntohs(uh->destination_port) == 53)) {
		printf("Application type: DNS\n");
	}
	else if ((ntohs(uh->source_port) == 69) || (ntohs(uh->destination_port) == 69)) {
		printf("Application type: TFTP\n");
	}
	else if ((ntohs(uh->source_port) == 80) || (ntohs(uh->destination_port) == 80)) {
		printf("Application type: HTTP\n");
	}
	else if ((ntohs(uh->source_port) == 111) || (ntohs(uh->destination_port) == 111)) {
		printf("Application type: RPC\n");
	}
	else if ((ntohs(uh->source_port) == 123) || (ntohs(uh->destination_port) == 123)) {
		printf("Application type: NTP\n");
	}
	else if ((ntohs(uh->source_port) == 161) || (ntohs(uh->destination_port) == 161)) {
		printf("Application type: SNMP\n");
	}
	else if ((ntohs(uh->source_port) == 162) || (ntohs(uh->destination_port) == 162)) {
		printf("Application type: SNMP\n");
	}
	else if ((ntohs(uh->source_port) == 443) || (ntohs(uh->destination_port) == 443)) {
		printf("Application type: QUIC\n");
	}
	else if ((ntohs(uh->source_port) == 1900) || (ntohs(uh->destination_port) == 1900)) {
		printf("Application type: SSDP\n");
	}

	if (UDP < ntohs(uh->total_length) - 8) {
		UDP = ntohs(uh->total_length) - 8;
	}
}
