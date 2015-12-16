#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdarg.h>

#define IPHEADERLEN 20
#define IPADDRLEN 16

int count_packets(FILE *fp) {
	int count = 0;
	long length = 2L;
	unsigned char bytes[2];
	fseek(fp, length, SEEK_SET);
	
	while (fread(bytes, sizeof(char), 2, fp) == 2) {
		length += (bytes[0] << 8) | bytes[1];
		fseek(fp, length, SEEK_SET);
		count++;
	}
	
	if (!feof(fp)) {
		return -1;
	}
	
	return count;
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
	
	unsigned char bytes[IPHEADERLEN];
	fread(bytes, sizeof(char), IPHEADERLEN, fp);
	
	char srcaddr[IPADDRLEN];
	snprintf(srcaddr, IPADDRLEN, "%u.%u.%u.%u", bytes[12], bytes[13], bytes[14], bytes[15]);
	
	char destaddr[IPADDRLEN];
	snprintf(destaddr, IPADDRLEN, "%u.%u.%u.%u", bytes[16], bytes[17], bytes[18], bytes[19]);
	
	unsigned char ihl = bytes[0] & 0x0F;
	unsigned short int packetlen = (bytes[2] << 8) | bytes[3];
	
	fseek(fp, (ihl * 4) + 12, SEEK_SET);
	fread (bytes, sizeof(char), 1, fp);
	unsigned char tcphl = (bytes[0] & 0xF0) >> 4;
	
	int npackets = count_packets(fp);
	
	if (npackets < 0) {
		perror("Error reading log file");
		return 3;
	}
	
	printf("%s %s %u %u %u %d\n", srcaddr, destaddr, ihl, packetlen, tcphl, npackets);
	return 0;
}
