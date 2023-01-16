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

int parsePacket(FILE *fp);
void parseEthernet(char *buffer);
void viewMAC(unsigned char *mac);
void parseIP(char *buffer);

int parsePacket(FILE *fp) {
	char buffer[65536];
	int count = 0;

	PFHeader pfh;
	fread(&pfh, sizeof(pfh), 1, fp);

	PHeader pheader[3001];
	PHeader *ph = pheader;

	while ((feof(fp) == 0) && (fread(ph, sizeof(PHeader), 1, fp) == 1)) {

		count++;
		if (count == 3000) {
			break;
		}

		time_t time = ph->sec;
		struct tm* t;
		t = (struct tm*)localtime(&time);

		printf("==========================================================================================\n");
		printf("\n[Frame %d] (Local time - %02d:%02d:%02d.%06d)\n", count, t->tm_hour, t->tm_min, t->tm_sec, ph->usec);
		printf("%u bytes on wire (%u bits), %u bytes captured (%u bits).\n", ph->packet_len, 8 * (ph->packet_len), ph->capture_len, 8 * (ph->capture_len));

		fread(buffer, 1, ph->capture_len, fp);
		parseEthernet(buffer);
		ph++;
		printf("\n");
	}

	return 0;
}

void parseEthernet(char *buffer) {
	Ethernet_Header* eh = (Ethernet_Header*)buffer;

	printf("Source MAC address: ");
	viewMAC(eh->src_mac);

	printf(" -> ");

	printf("Destination MAC address: ");
	viewMAC(eh->dst_mac);
	printf("\n");

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

void viewMAC(unsigned char *mac) {
	printf("(%02x", mac[0]);
	for (int i = 1; i < 6; i++) {
		printf(":%02x", mac[i]);
	}
	printf(")");
}

void parseIP(char *buffer) {
	struct in_addr addr;
	IP_Header* ih = (IP_Header*)buffer;

	addr.s_addr = ih->src_addr;
	printf("Source IP address: %s", inet_ntoa(addr));

	printf(" -> ");

	addr.s_addr = ih->dst_addr;
	printf("Destination IP address: %s\n", inet_ntoa(addr));

	printf("IP Header Length: %d bytes\n", ih->header_len * 4);

	printf("IP Total Length: %d\n", ntohs(ih->total_len));

	printf("Identfication: %d\n", ntohs(ih->identification));

	if ((ih->fragmentation) & 0x40) {
		printf("Flags: Don't fragment\n");
	}
	else if ((ih->fragmentation) & 0x20) {
		printf("Flags: More fragments\n");
	}
	else {
		printf("Flags: DF & MF are not set\n");
	}

	printf("Fragment-offset: %d (%d)\n", ntohs((ih->fragmentation) & (0xFF1F)), 8 * ntohs((ih->fragmentation) & (0xFF1F)));

	printf("Time to Live: %d\n", ih->time_to_live);

	if (ih->protocol == 1) {
		printf("Protocol: ICMP (%d)\n", ih->protocol);
	}
	else if (ih->protocol == 6) {
		printf("Protocol: TCP (%d)\n", ih->protocol);
	}
	else if (ih->protocol == 17) {
		printf("Protocol: UDP (%d)\n", ih->protocol);
	}
	else {
		printf("Protocol Number: %d\n", ih->protocol);
	}
}

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

	return 0;
}