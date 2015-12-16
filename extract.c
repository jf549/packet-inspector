#include <stdio.h>
#include <string.h>

#define WORDSIZE 4

int extract_data(FILE *in, FILE *out) {
	long fileindex = 0L;
	unsigned char word[WORDSIZE];
	
	while ((fread(word, sizeof(char), WORDSIZE, in)) == WORDSIZE) {
		unsigned char ihl = (word[0] & 0x0F) * 4;
		unsigned short int packetlen = (word[2] << 8) | word[3];
		
		//seek to TCP header data offset field
		fseek(in, fileindex + ihl + 12, SEEK_SET);
		
		if (fread(word, sizeof(char), 1, in) != 1) {
			perror("Failed to read tcp header data from log file");
			return 2;
		}
		
		unsigned char tcphl = (word[0] & 0xF0) >> 2;
		
		//seek to data
		fseek(in, fileindex + ihl + tcphl, SEEK_SET);
		
		unsigned short int datalen = packetlen - ihl - tcphl;
		unsigned char buf[datalen];
		
		if (fread(buf, sizeof(char), datalen, in) != datalen) {
			perror("Failed to read data from log file");
			return 3;
		}
		
		if (fwrite(buf, sizeof(char), datalen, out) != datalen) {
			perror("Failed to write data to output file");
			return 4;
		}
		
		//seek to next packet
		fileindex += packetlen;
		fseek(in, fileindex, SEEK_SET);
	}
	
	if (!feof(in)) {
		perror("Failed to read ip header data from log file");
		return 1;
	}
	
	return 0;
}

int main(int argc, char const *argv[]) {
	if (argc != 3) {
		perror("Usage: extract <log file> <output file>");
		return 1;
	}
	
	FILE *in, *out;
	
	if ((in = fopen(argv[1], "rb")) == 0) {
		perror("Failed to open log file");
		return 2;
	}
	
	if ((out = fopen(argv[2], "wb")) == 0) {
		perror("Failed to open/create output file");
		return 3;
	}
	
	return extract_data(in, out);
}
