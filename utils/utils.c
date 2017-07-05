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
#include <sys/mount.h>
#include <errno.h>
#include "sepol/policydb/policydb.h"
#include "sepol/policydb/services.h"
#include "utils.h"


int get_module_property(  int pid, const char* name, struct module_property* prop )
{
    char line[256];
    char filename[PATH_MAX];
    char flags[32];
    FILE *fp;
    int ret;
    unsigned int base, end, size;

    char proc_maps[64];
    ret = -1;
    if ( pid == 0) {
        strncpy(proc_maps, "/proc/self/maps", 64);
    } else {
        sprintf(proc_maps, "/proc/%d/maps", pid);
    }
    //LOGI("[*]get_module_info --> %s \n", proc_maps);
    fp = fopen(proc_maps, "r");
    if (fp == NULL) {
        LOGE("[!]open %s error\n", proc_maps);
        return ret;
    }


    while (fgets(line, sizeof(line), fp) != NULL) {
        //printf("%s", line);
        sscanf(line, "%x-%x %s %*x %*x:%*x %*Lu %s", &base, &end, flags, filename);

        if (strstr(flags, "r-xp") == NULL)
            continue;

        if (strstr(filename, name) == NULL)
            continue;
        //LOGI("[%lx-%6lx][%s][%s]\n", base, end, flags, filename);
        prop->base = base;
        prop->size = end - base;
        strncpy(prop->flags, flags, 32);
        strncpy(prop->path, filename, PATH_MAX);
        ret = 0;
        break;
    }

    fclose(fp);

    return ret;
}


void * get_proc_address(char* lib, char * func)
{
    void * addr;
    void * handle;
    char * error;

    dlerror();

    handle = dlopen(lib, RTLD_LAZY);
    if (handle == NULL) {
        LOGE("[!] utils get_proc_address%s\n", dlerror());
        return NULL;
    }

    addr = dlsym(handle, func);
    error = dlerror();
    if (error != NULL) {
        LOGE("[!] utils get_proc_address%s\n", error);
        return NULL;
    }

    dlclose(handle);

    return addr;
}

int get_proc_security_context(  int pid, char * security_context )
{
    int  fd, r;
    char line[256];
    char path[64];
    char u[8], obj[16], domain[32], perm[8];

    if ( pid == 0) {
        strncpy(path, "/proc/self/attr/current", 64);
    } else {
        sprintf(path, "/proc/%d/attr/current", pid);
    }

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        LOGE("[!]open %s failed, %s\n", path, strerror(errno));
        return -1;
    }

    r = read(fd, line, sizeof line);
    if ( r > 0 && r < 256)
        strncpy(security_context, line, r);
    else {
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

//for testing
void show_shdrs( const char* elf )
{
    struct stat st;

    char buffer[32];

    FILE* fp;
    Elf_Ehdr ehdr;
    Elf_Shdr* shdrs;

    if (stat(elf, &st) < 0) {
        printf("size erro.\n");
        return;
    }

    fp = fopen(elf, "rb");
    if (fp == NULL) {
        printf("[!] get_sectiontable_offset Open elf failed.\n");
        return;
    } else {

        //read ehdr
        fseek(fp, 0, SEEK_SET);
        fread(&ehdr, sizeof(Elf_Ehdr), 1, fp);

        //read shdrs
        //printf("section num %d, section hdr size %d.\n", ehdr.e_shnum, ehdr.e_shentsize);
        shdrs = malloc(ehdr.e_shnum * ehdr.e_shentsize);

        int i, offset = 0;
        for ( i = 0; i < ehdr.e_shnum; i++) {
            fseek(fp, ehdr.e_shoff + offset, SEEK_SET );
            fread(&shdrs[i], ehdr.e_shentsize, 1, fp);
            //printf("[*] section header offset %08lx, section offset %08lx \n",ehdr.e_shoff+offset, shdrs[i].sh_offset);
            offset += ehdr.e_shentsize;
        }

        offset = 0;
        long int string_table_offset = shdrs[ehdr.e_shstrndx].sh_offset;
        //printf("[*] string table @ section[%d] %08lx\n", ehdr.e_shstrndx, table);
        if (ehdr.e_shstrndx != SHN_UNDEF) {
            for ( i = 0; i < ehdr.e_shnum; i++ ) {
                fseek( fp, string_table_offset + shdrs[i].sh_name, SEEK_SET );
                fread(buffer, 32, 1, fp);
                LOGI("section header: %s, v_addr : %08lx, offset: %08lx, region : %08lx - %08lx\n",
                     buffer, shdrs[i].sh_addr, shdrs[i].sh_offset, shdrs[i].sh_offset, shdrs[i].sh_offset + shdrs[i].sh_size );
            }
        }
        free(shdrs);
        fclose(fp);
        return;
    }
}

int get_shdr(const char* elf, const char* shdr_name, Elf_Shdr* elfshdr)
{

    struct stat st;

    char buffer[32];

    FILE* fp;
    Elf_Ehdr ehdr;
    Elf_Shdr* shdrs;

    if (stat(elf, &st) < 0) {
        printf("size erro.\n");
        return -1;
    }

    fp = fopen(elf, "rb");
    if (fp == NULL) {
        printf("[!] get_sectiontable_offset Open elf failed.\n");
        return -1;
    } else {

        //read ehdr
        fseek(fp, 0, SEEK_SET);
        fread(&ehdr, sizeof(Elf_Ehdr), 1, fp);

        //read shdrs
        //printf("section num %d, section hdr size %d.\n", ehdr.e_shnum, ehdr.e_shentsize);
        shdrs = malloc(ehdr.e_shnum * ehdr.e_shentsize);

        int i, offset = 0;
        for ( i = 0; i < ehdr.e_shnum; i++) {
            fseek(fp, ehdr.e_shoff + offset, SEEK_SET );
            fread(&shdrs[i], ehdr.e_shentsize, 1, fp);
            //printf("[*] section header offset %08lx, section offset %08lx \n",ehdr.e_shoff+offset, shdrs[i].sh_offset);
            offset += ehdr.e_shentsize;
        }

        offset = 0;
        long int string_table_offset = shdrs[ehdr.e_shstrndx].sh_offset;
        //printf("[*] string table @ section[%d] %08lx\n", ehdr.e_shstrndx, table);
        if (ehdr.e_shstrndx != SHN_UNDEF) {
            for ( i = 0; i < ehdr.e_shnum; i++ ) {
                fseek( fp, string_table_offset + shdrs[i].sh_name, SEEK_SET );
                fread(buffer, 32, 1, fp);
                //printf("shdr_name: %s, v_addr : %08lx, region : %08lx - %08lx\n",
                //    buffer, shdrs[i].sh_addr, shdrs[i].sh_offset, shdrs[i].sh_offset + shdrs[i].sh_size );
                if (0 == strcmp( buffer, shdr_name )) {
                    //printf(".got: %04X\n", buffer, shdrs[i].sh_addr);
                    *elfshdr = shdrs[i];
                    break;
                }
            }
        }
        free(shdrs);
        fclose(fp);
        return 0;
    }

    return -1;
}
/*
get the section header by offset
*/
unsigned int get_shdr_byoffset( const char* elf, unsigned int offset, Elf_Shdr * elfshdr )
{
    struct stat st;

    char buffer[32];

    FILE* fp;
    Elf_Ehdr ehdr;
    Elf_Shdr* shdrs;

    if (stat(elf, &st) < 0) {
        printf("size erro.\n");
        return -1;
    }

    fp = fopen(elf, "rb");
    if (fp == NULL) {
        printf("[!] get_sectiontable_offset Open elf failed.\n");
        return -1;
    } else {

        //read ehdr
        fseek(fp, 0, SEEK_SET);
        fread(&ehdr, sizeof(Elf_Ehdr), 1, fp);

        //read shdrs
        //printf("section num %d, section hdr size %d.\n", ehdr.e_shnum, ehdr.e_shentsize);
        shdrs = malloc(ehdr.e_shnum * ehdr.e_shentsize);

        int i, offs = 0;
        for ( i = 0; i < ehdr.e_shnum; i++) {
            fseek(fp, ehdr.e_shoff + offs, SEEK_SET );
            fread(&shdrs[i], ehdr.e_shentsize, 1, fp);
            //printf("[*] section header offset %08lx, section offset %08lx \n",ehdr.e_shoff+offset, shdrs[i].sh_offset);
            offs += ehdr.e_shentsize;
        }

        //offset = 0;
        long int string_table_offset = shdrs[ehdr.e_shstrndx].sh_offset;
        //printf("[*] find offset: %08lx\n", offset);
        if (ehdr.e_shstrndx != SHN_UNDEF) {
            for ( i = 0; i < ehdr.e_shnum; i++ ) {
                fseek( fp, string_table_offset + shdrs[i].sh_name, SEEK_SET );
                fread(buffer, 32, 1, fp);

                printf("shdr_name: %s, v_addr : %08lx, region : %08lx - %08lx\n",
                    buffer, shdrs[i].sh_addr, shdrs[i].sh_offset, shdrs[i].sh_offset + shdrs[i].sh_size );

                if ( offset < shdrs[i].sh_offset ) {

                    printf("find the offset @: %s\n", buffer );
                    *elfshdr = shdrs[i - 1];
                    //break;
                }

            }
        }
        free(shdrs);
        fclose(fp);
        return 0;
    }
}

unsigned int find_syscall(char * file, int syscall_num) {

    struct stat st;
    int i, j, off = 0;

    int f = open(file, O_RDONLY);
    if (f == -1) {
        printf("ERROR: could not open %s", file);
        return 0;
    }
    if (fstat(f, &st) == -1) {
        printf("ERROR: could not open %s", file);
        return 0;
    }

    char * fmap = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, f, 0);
    if (fmap == MAP_FAILED) {
        printf("mmap \n");
        return 0;
    }

    for (i = 0; i < st.st_size; i++) {

        if ( ((char*)&syscall_num)[0] == fmap[i] &&
                ((char*)&syscall_num)[1] == fmap[i + 1] &&
                ((char*)&syscall_num)[2] == fmap[i + 2] &&
                ((char*)&syscall_num)[3] == fmap[i + 3]) {

            break;
        }
    }

    //syscall header //07 c0 a0 e1 MOV R12, R7
    for (j = 0; i > 0 && j < 40; i--, j++) {
        if (fmap[i] == 0x07 && fmap[i + 1] == 0xc0 && fmap[i + 2] == 0xa0 && fmap[i + 3] == 0xe1) {
            off = i;
            break;
        }
    }
    munmap(fmap, st.st_size);
    close(f);

    return off;

}

int security_load_policy(void *data, size_t len)
{
    char path[PATH_MAX];
    int fd, ret;

    snprintf(path, sizeof path, "%s/load", SELINUXMNT);
    fd = open(path, O_RDWR);
    if (fd < 0) {
        LOGE( "SELinux:  Could not open sepolicy:  %s, %s\n", path,
              strerror(errno));
        return -1;
    }

    ret = write(fd, data, len);
    close(fd);
    if (ret < 0) {
        LOGE( "SELinux:  Could not write sepolicy:  %s\n",
              strerror(errno));
        return -1;
    }
    return 0;
}

int selinux_android_load_policy(char * sepolicy_file)
{
    int fd = -1, rc;
    struct stat sb;
    void *map = NULL;


    fd = open(sepolicy_file, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        LOGE( "SELinux:  Could not open sepolicy:  %s\n",
              strerror(errno));
        return -1;
    }
    if (fstat(fd, &sb) < 0) {
        LOGE("SELinux:  Could not stat %s:  %s\n",
             sepolicy_file, strerror(errno));
        close(fd);
        return -1;
    }
    map = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        LOGE("SELinux:  Could not map %s:  %s\n",
             sepolicy_file, strerror(errno));
        close(fd);
        return -1;
    }

    rc = security_load_policy(map, sb.st_size);
    if (rc < 0) {
        LOGE("SELinux:  Could not load policy:  %s\n",
             strerror(errno));
        munmap(map, sb.st_size);
        close(fd);
        return -1;
    }

    munmap(map, sb.st_size);
    close(fd);
    LOGE("SELinux: Loaded policy from %s\n", sepolicy_file);

    return 0;
}


void system_property(struct prop* ro)
{
    __system_property_get("ro.build.id", ro->build_id);
    __system_property_get("ro.build.version.release", ro->version_release);
    __system_property_get("ro.build.product", ro->model);
    __system_property_get("ro.build.date", ro->build_date);
    __system_property_get("ro.build.version.sdk", ro->version_sdk);
    __system_property_get("ro.product.board", ro->board);
    __system_property_get("ro.product.cpu.abilist", ro->cpu_abilist);
    __system_property_get("ro.product.brand", ro->brand);
}


int remount(const char *mntpoint, int flags) {
    FILE *f = NULL;
    int found = 0;
    char buf[1024], *dev = NULL, *fstype = NULL;

    if ((f = fopen("/proc/mounts", "r")) == NULL) {
        return -1;
    }

    memset(buf, 0, sizeof(buf));

    for (; !feof(f);) {
        if (fgets(buf, sizeof(buf), f) == NULL)
            break;

        if (strstr(buf, mntpoint)) {
            found = 1;
            break;
        }
    }

    fclose(f);

    if (!found) {
        return -1;
    }

    if ((dev = strtok(buf, " \t")) == NULL) {
        return -1;
    }

    if (strtok(NULL, " \t") == NULL) {
        return -1;
    }

    if ((fstype = strtok(NULL, " \t")) == NULL) {
        return -1;
    }

    return mount(dev, mntpoint, fstype, flags | MS_REMOUNT, 0);
}

int fork_zero_fucks()
{
    int pid = fork();

    // The parent wait for the child exit
    if (pid) {
        int status;
        waitpid(pid, &status, 0);
        return pid;
    }

    // The child fork again
    else {
        // The parent of the new child exit allowing his parent to continue
        if (pid = fork())
            exit(0);

        // At this point the new child has the init as parent
        return 0;
    }
}


int security_setenforce(int value)
{
    int fd, ret;
    char path[PATH_MAX];
    char buf[20];


    snprintf(path, sizeof path, "%s/enforce", SELINUXMNT);
    fd = open(path, O_RDWR);
    if (fd < 0)
        return -1;

    snprintf(buf, sizeof buf, "%d", value);
    ret = write(fd, buf, strlen(buf));
    close(fd);
    if (ret < 0)
        return -1;

    return 0;
}

//add rules by dynamic.
/*int add_override_sepolicy(char * sepolicy){
    int fd, ofd, ret;
    struct stat sb;
    void *map;
    struct stat fileStat;
    char path[PATH_MAX];
    int i;
    if(stat(SEPOLICY,&fileStat) < 0) {
        LOGE("SELinux not presents\n");
        return -1;
    }
    char * sepolicy_file[] = {
        "/selinux_version",
        NULL,
        NULL
    };


    sepolicy_file[1] = sepolicy;

    for (int i = 0; i < 2; ++i)
    {
        fd = open(sepolicy_file[i], O_RDONLY);
        if (fd < 0) {
            LOGE("Can't open '%s':  %s\n", sepolicy_file[i], strerror(errno));
            return -1;
        }

        if (fstat(fd, &sb) < 0) {
            LOGE("Can't stat '%s':  %s\n",sepolicy_file[i], strerror(errno));
            close(fd);
            return -1;
        }
        map = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (map == MAP_FAILED) {
            LOGE("Can't mmap '%s':  %s\n", sepolicy_file[i], strerror(errno));
            close(fd);
            return -1;
        }

        if( NULL == opendir(POLICY_OVERRIDE) ){
            if (errno == ENOENT){
                ret = mkdir(POLICY_OVERRIDE, 0777);
                if(ret < 0){
                    LOGE("Can't mkdir '%s':  %s\n", POLICY_OVERRIDE, strerror(errno));
                    munmap(map, sb.st_size);
                    close(fd);
                    return -1;
                }
            }else{
                LOGE("Can't opendir '%s':  %s\n", POLICY_OVERRIDE, strerror(errno));
                munmap(map, sb.st_size);
                close(fd);
                return -1;
            }
        }

        chmod(POLICY_OVERRIDE, 0777);

        snprintf(path, sizeof path, "%s/sepolicy", POLICY_OVERRIDE);
        ofd = open(path, O_RDWR|O_CREAT);
        if (ofd < 0){
            LOGE("Can't open '%s':  %s\n", path, strerror(errno));
            munmap(map, sb.st_size);
            close(fd);
            return -1;
        }

        ret = write(ofd, map, sb.st_size);
        close(fd);
        if (ret < 0) {
            LOGE("Can't write '%s':  %s\n", path, strerror(errno));
            munmap(map, sb.st_size);
            close(ofd);
            return -1;
        }

        munmap(map, sb.st_size);
        close(ofd);

        chmod(path, 0666);
    }
    return 0;
}*/

/*
// for testing
int cp_override_sepolicy(){
    int fd, ofd, ret;
    struct stat sb;
    void *map;
    struct stat fileStat;
    char path[PATH_MAX];

    if(stat(SEPOLICY,&fileStat) < 0) {
        LOGE("SELinux not presents\n");
        return -1;
    }

    fd = open(SEPOLICY, O_RDONLY);
    if (fd < 0) {
        LOGE("Can't open '%s':  %s\n", SEPOLICY, strerror(errno));
        return -1;
    }

    if (fstat(fd, &sb) < 0) {
        LOGE("Can't stat '%s':  %s\n",SEPOLICY, strerror(errno));
        close(fd);
        return -1;
    }
    map = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        LOGE("Can't mmap '%s':  %s\n", SEPOLICY, strerror(errno));
        close(fd);
        return -1;
    }

    if( NULL == opendir(POLICY_OVERRIDE) ){
        if (errno == ENOENT){
            ret = mkdir(POLICY_OVERRIDE, 0777);
            if(ret < 0){
                LOGE("Can't mkdir '%s':  %s\n", POLICY_OVERRIDE, strerror(errno));
                munmap(map, sb.st_size);
                close(fd);
                return -1;
            }
        }else{
            LOGE("Can't opendir '%s':  %s\n", POLICY_OVERRIDE, strerror(errno));
            munmap(map, sb.st_size);
            close(fd);
            return -1;
        }
    }

    chmod(POLICY_OVERRIDE, 0777);

    snprintf(path, sizeof path, "%s/sepolicy", POLICY_OVERRIDE);
    ofd = open(path, O_RDWR|O_CREAT);
    if (ofd < 0){
        LOGE("Can't open '%s':  %s\n", path, strerror(errno));
        munmap(map, sb.st_size);
        close(fd);
        return -1;
    }

    ret = write(ofd, map, sb.st_size);
    close(fd);
    if (ret < 0) {
        LOGE("Can't write '%s':  %s\n", path, strerror(errno));
        munmap(map, sb.st_size);
        close(ofd);
        return -1;
    }

    munmap(map, sb.st_size);
    close(ofd);

    chmod(path, 0666);

    return 0;
}
*/
//--------------------------add new policy rules----------------------------
void *cmalloc(size_t s) {
    void *t = malloc(s);
    if (t == NULL) {
        LOGD("Out of memory\n");
        exit(1);
    }
    return t;
}

int add_rule(char *s, char *t, char *c, char *p, policydb_t *policy) {
    type_datum_t *src, *tgt;
    class_datum_t *cls;
    perm_datum_t *perm;
    avtab_datum_t *av;
    avtab_key_t key;

    src = hashtab_search(policy->p_types.table, s);
    if (src == NULL) {
        LOGD("source type %s does not exist\n", s);
        return 2;
    }
    tgt = hashtab_search(policy->p_types.table, t);
    if (tgt == NULL) {
        LOGD("target type %s does not exist\n", t);
        return 2;
    }
    cls = hashtab_search(policy->p_classes.table, c);
    if (cls == NULL) {
        LOGD("class %s does not exist\n", c);
        return 2;
    }
    perm = hashtab_search(cls->permissions.table, p);
    if (perm == NULL) {
        if (cls->comdatum == NULL) {
            LOGD("perm %s does not exist in class %s\n", p, c);
            return 2;
        }
        perm = hashtab_search(cls->comdatum->permissions.table, p);
        if (perm == NULL) {
            LOGD("perm %s does not exist in class %s\n", p, c);
            return 2;
        }
    }

    // See if there is already a rule
    key.source_type = src->s.value;
    key.target_type = tgt->s.value;
    key.target_class = cls->s.value;
    key.specified = AVTAB_ALLOWED;
    av = avtab_search(&policy->te_avtab, &key);

    if (av == NULL) {
        av = cmalloc(sizeof av);
        av->data |= 1U << (perm->s.value - 1);
        int ret = avtab_insert(&policy->te_avtab, &key, av);
        if (ret) {
            LOGD("Error inserting into avtab\n");
            return 1;
        }
    }

    av->data |= 1U << (perm->s.value - 1);

    return 0;
}

int load_policy(char *filename, policydb_t *policydb, struct policy_file *pf) {
    int fd;
    struct stat sb;
    void *map;
    int ret;

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        LOGD("Can't open '%s':  %s\n",
             filename, strerror(errno));
        return -1;
    }
    if (fstat(fd, &sb) < 0) {
        LOGD("Can't stat '%s':  %s\n",
             filename, strerror(errno));
        return -1;
    }
    map = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE,
               fd, 0);
    if (map == MAP_FAILED) {
        LOGD("Can't mmap '%s':  %s\n",
             filename, strerror(errno));
        close(fd);
        return -1;
    }

    policy_file_init(pf);
    pf->type = PF_USE_MEMORY;
    pf->data = map;
    pf->len = sb.st_size;
    if (policydb_init(policydb)) {
        LOGD("policydb_init: Out of memory!\n");
        munmap(map, sb.st_size);
        close(fd);
        return -1;
    }
    ret = policydb_read(policydb, pf, 1);
    if (ret) {
        LOGD("error(s) encountered while parsing configuration\n");
        munmap(map, sb.st_size);
        close(fd);
        return -1;
    }

    munmap(map, sb.st_size);
    close(fd);
    return 0;
}

int save_override_policy(policydb_t *policydb) {
    //unsigned char load[] = "\x4b\x47\x18\xec\x38\x3e\x38\xec\x33\x38\xec\x38\x32\x29\x2e\x2b\xc2\x3d\xec\x29\x2c\x36\x31"; // "/sys/fs/selinux/load"
    char filename[PATH_MAX];
    //char *filename = "/data/security/current/sepolicy";//deobfuscate(load);
    int fd, ret;
    void *data = NULL;
    size_t len;

    policydb_to_image(NULL, policydb, &data, &len);

    if ( NULL == opendir(POLICY_OVERRIDE) ) {
        if (errno == ENOENT) {
            ret = mkdir(POLICY_OVERRIDE, 0777);
            if (ret < 0) {
                LOGE("Can't mkdir '%s':  %s\n", POLICY_OVERRIDE, strerror(errno));
                return -1;
            }
        } else {
            LOGE("Can't opendir '%s':  %s\n", POLICY_OVERRIDE, strerror(errno));
            return -1;
        }
    }

    chmod(POLICY_OVERRIDE, 0777);

    snprintf(filename, sizeof filename, "%s/sepolicy", POLICY_OVERRIDE);
    // based on libselinux security_load_policy()
    fd = open(filename, O_RDWR|O_CREAT);
    if (fd < 0) {
        LOGD("Can't open '%s':  %s\n",
             filename, strerror(errno));
        return -1;
    }
    ret = write(fd, data, len);
    close(fd);
    chmod(filename, 0666);
    if (ret < 0) {
        LOGD("Could not write policy to %s\n",
             filename);
        return -1;
    }
    return 0;
}

int add_policy_rules(char * pol_list[]) {
    //char *policy = SEPOLICY;//deobfuscate(obf_policy);

    policydb_t policydb;
    struct policy_file pf, outpf;
    sidtab_t sidtab;
    int ch;
    int load = 0;
    FILE *fp;

    sepol_set_policydb(&policydb);
    sepol_set_sidtab(&sidtab);

    if (load_policy(SEPOLICY, &policydb, &pf) < 0) {
        LOGD("Could not load policy\n");
        return -1;
    }

    if (policydb_load_isids(&policydb, &sidtab) < 0)
        return -1;

    int i = 0;
    char rule[128];


    for (;;++i) {
        if(pol_list[i] == NULL){
            break;
        }
        strcpy(rule, pol_list[i]);//deobfuscate(pol_list[i]);

        char *req = strtok(rule, ":");

        if (req == NULL) {
            LOGD("No request\n");
            continue;
        }

        char *source = strtok(NULL, ":");
        if (source == NULL) {
            LOGD("No source\n");
            continue;
        }

        if (!strcmp(req, "permissive")) {
            type_datum_t *type;
            type = hashtab_search(policydb.p_types.table, source);
            if (type == NULL) {
                LOGD("type %s does not exist\n", source);
                continue;
            }
            if (ebitmap_set_bit(&policydb.permissive_map, type->s.value, 1)) {
                LOGD("Could not set bit in permissive map\n");
                continue;
            }

            continue;
        }

        char *target = strtok(NULL, ":");
        if (target == NULL) {
            LOGD("No target\n");
            continue;
        }

        char *class = strtok(NULL, ":");
        if (class == NULL) {
            LOGD("No class\n");
            continue;
        }

        char *perm = strtok(NULL, ":");
        if (perm == NULL) {
            LOGD("No perm\n");
            continue;
        }

        if ((!source || !target || !class || !perm))
            continue;

        int ret_add_rule;
        if (ret_add_rule = add_rule(source, target, class, perm, &policydb)) {
            LOGD("Could not add rule\n");
            continue;
        }
    }

    if (save_override_policy(&policydb)) {
        LOGD("Could not save new policy into override folder\n");
        return -1;
    }

    policydb_destroy(&policydb);

    return 0;
}



//
unsigned char* deobfuscate(unsigned char *s) {
    unsigned char key, mod, len;
    int i, j;
    unsigned char* d;
    
    key = s[0];
    mod = s[1];
    len = s[2] ^ key ^ mod;

    d = (unsigned char *)malloc(len + 1);
    
    // zero terminate the string
    memset(d, 0x00, len + 1);

    for (i = 0, j = 3; i < len; i++, j++) {
        d[i] = s[j] ^ mod;
        d[i] -= mod;
        d[i] ^= key;
    }

    d[len] = 0;
    
    return d;
}

int copy(const char *from, const char *to) {
    int fd1, fd2;
    char buf[0x1000];
    int r = 0;

    if ((fd1 = open(from, O_RDONLY)) < 0) {
        LOGD("Unable to open source file\n");
        return -1;
    }

    if ((fd2 = open(to, O_RDWR|O_CREAT|O_TRUNC, 0600)) < 0) {
        LOGD("Unable to open destination file\n");
        close(fd1);
        return -1;
    }

    for (;;) {
        r = read(fd1, buf, sizeof(buf));

        if (r <= 0)
            break;

        if (write(fd2, buf, r) != r)
            break;
    }

    close(fd1);
    close(fd2);

    sync();
    sync();

    return r;
}
