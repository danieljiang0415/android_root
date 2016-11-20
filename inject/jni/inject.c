
#include <stdio.h>
#include <pthread.h>

#include <android/log.h>

#define TAG "inject"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG,TAG ,__VA_ARGS__) // 定义LOGD类型   
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,TAG ,__VA_ARGS__) // 定义LOGI类型   
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,TAG ,__VA_ARGS__) // 定义LOGW类型   
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,TAG ,__VA_ARGS__) // 定义LOGE类型   
#define LOGF(...) __android_log_print(ANDROID_LOG_FATAL,TAG ,__VA_ARGS__) // 定义LOGF类型

void my_init(void) __attribute__((constructor)); //告诉gcc把这个函数扔到init section  
void my_fini(void) __attribute__((destructor));  //告诉gcc把这个函数扔到fini section
void out_msg(const char *m)
{  
	while(1) {
		//system("echo helloworld! > /data/local/tmp/hell.txt");

		sleep(2);
		//system("reboot");
        LOGI("[*] I'm injcet in %d", getpid());
		
	}
      
}  

void my_init(void)  
{
	//system("echo helloworld! > /data/local/tmp/hell.txt");
    char buf[1024] = { 0 };
    int n;
 
    n = readlink("/proc/self/exe" , buf , sizeof(buf));
    if( n > 0 && n < sizeof(buf))
    {
        LOGI("%s\n" , buf);
    }
    pthread_t pth1;

	pthread_create(&pth1, NULL, out_msg, NULL);
 
}  
void my_fini(void)  
{  
 
    printf("    Fini \n");  
 
}
