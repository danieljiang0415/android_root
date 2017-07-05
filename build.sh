
#!/system/bin/sh

ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk NDK_APPLICATION_MK=Application.mk

#arm/as -o state1/loadpolicy.o stage1/loadpolicy.as

adb push libs/armeabi/dirtycow /data/local/tmp
adb push libs/armeabi/inject /data/local/tmp
adb push libs/armeabi/libcore.so /data/local/tmp
adb push ./run.sh /data/local/tmp
adb shell chmod 777 /data/local/tmp/run.sh

adb push ./sepolicy.sh /data/local/tmp
adb shell chmod 777 /data/local/tmp/sepolicy.sh

adb push libs/armeabi/su /data/local/tmp
adb shell chmod 777 /data/local/tmp/su

adb push tool/sepolicy-inject /data/local/tmp
adb push tool/sesearch /data/local/tmp
adb shell chmod 777 /data/local/tmp/sesearch