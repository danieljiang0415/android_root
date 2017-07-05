#ifndef _UTILS_H_
#define _UTILS_H_

#include <elf.h>
#include <android/log.h>

#ifndef ARCH_64
	typedef Elf32_Shdr Elf_Shdr;
	typedef Elf32_Ehdr Elf_Ehdr;
#else
	typedef Elf64_Shdr Elf_Shdr;
	typedef Elf64_Ehdr Elf_Ehdr;
#endif

#define TAG "ldpo"
#ifdef DEBUG
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG,TAG ,__VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,TAG ,__VA_ARGS__) 
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,TAG ,__VA_ARGS__) 
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,TAG ,__VA_ARGS__) 
#define LOGF(...) __android_log_print(ANDROID_LOG_FATAL,TAG ,__VA_ARGS__) 
#else
#define LOGD(...) 
#define LOGI(...) 
#define LOGW(...) 
#define LOGE(...) 
#define LOGF(...)
#endif


// library info refer
struct module_property{
	unsigned int base;
	unsigned int size;
	char        flags[32];
	char 		path[PATH_MAX];
};


void * get_proc_address(char* lib, char * funame);
/*unsigned int get_module_address(int pid, char* lib);
unsigned int get_module_length(int pid, char* lib);
void * get_module_path(char* lib, char* path);*/
int get_module_property(int pid, const char* name, struct module_property* prop);


// elf rerer
void show_shdrs( const char* elf );
int get_shdr(const char* elf, const char* shdr_name, Elf_Shdr* elfshdr);
unsigned int get_shdr_byoffset( const char* elf, unsigned int offset, Elf_Shdr * elfshdr );
unsigned int find_syscall(char * file, int syscall_num);



//selinux refer

#define SELINUXMNT "/sys/fs/selinux"
int selinux_android_load_policy(char * sepolicy_file);
int security_setenforce(int value);
int get_proc_security_context(  int pid, char * security_context );

#define SEPOLICY 			"/sepolicy"
#define SELINUX_VERSION 	"/selinux_version"
#define POLICY_OVERRIDE     "/data/security/current"
int add_policy_rules(char * rule[]);

//system infomation refer

struct prop {
	char build_id[64];
	char brand[64];
	char model[64];
	char build_date[256];
	char version_sdk[16];
	char version_release[16];
	char board[64];
	char cpu_abilist[64];
};

void system_property(struct prop*);


//file system operate

int remount(const char *mntpoint, int flags);
int copy(const char *from, const char *to);

//process
int fork_zero_fucks() ;


//
unsigned char* deobfuscate(unsigned char *s);
#endif