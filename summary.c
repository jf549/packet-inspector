#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdarg.h>

#define IPHEADERLEN 20
#define IPADDRLEN 16

int count_packets(FILE *fp) {
	int count = 0;
	long fileindex = 2L;
	unsigned char bytes[2];
	fseek(fp, fileindex, SEEK_SET);
	
	while (fread(bytes, sizeof(char), 2, fp) == 2) {
		count++;
		fileindex += (bytes[0] << 8) | bytes[1];
		fseek(fp, fileindex, SEEK_SET);
	}
	
	if (!feof(fp)) {
		perror("Failed to reach end of log file");
		return -1;
	}
	
	return count;
}

int print_summary(FILE *fp) {
	unsigned char bytes[IPHEADERLEN];
	
	if (fread(bytes, sizeof(char), IPHEADERLEN, fp) != IPHEADERLEN) {
		perror("Failed to read ip header data from log file");
		return 1;
	}
	
	unsigned char ihl = bytes[0] & 0x0F;
	unsigned short int packetlen = (bytes[2] << 8) | bytes[3];
	char srcaddr[IPADDRLEN];
	char destaddr[IPADDRLEN];
	snprintf(srcaddr, IPADDRLEN, "%u.%u.%u.%u", bytes[12], bytes[13], bytes[14], bytes[15]);
	snprintf(destaddr, IPADDRLEN, "%u.%u.%u.%u", bytes[16], bytes[17], bytes[18], bytes[19]);
	
	//seek to TCP data offset field
	fseek(fp, (ihl * 4) + 12, SEEK_SET);
	
	if (fread(bytes, sizeof(char), 1, fp) != 1) {
		perror("Failed to read tcp header data from log file");
		return 1;
	}
	
	unsigned char tcphl = (bytes[0] & 0xF0) >> 4;
	
	int npackets = count_packets(fp);
	
	if (npackets < 0) {
		return 1;
	}
	
	printf("%s %s %u %u %u %d\n", srcaddr, destaddr, ihl, packetlen, tcphl, npackets);
	
	return 0;
}

int main(int argc, char const *argv[]) {
	if (argc != 2) {
		perror("Usage: summary <file>");
		return 1;
	}
	
	FILE *fp;
	if ((fp = fopen(argv[1], "rb")) == 0) {
		perror("Cannot find log file");
		return 2;
	}
	
	return print_summary(fp);
}
