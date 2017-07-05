stage1---> 替换系统文件如adb-->检查是否替换成功!

stage2---> 修改libc.so, 调用dlopen加载adb, 等待获取root权限的进程!

stage3---> 修改init,patch seliux!

stage4---> stage2--->获取root shell--->su --daemon!
