#ROM<br />
#1,How to extract sony kernel and obtain symbol?<br />
binwalk zImage<br />
dd if=zImage bs=17248 skip=1 | gzip -cd > piggy<br />
./kallsymsprint '/home/daniel/Desktop/tegra/arch/arm/boot/piggy' > kallsyms.txt<br />

#Kernel<br />
#2, How to build android kernel for Nexus 5X?<br />
i,<br />
git checkout fe89f19<br />
<br />
ii,<br />
ARCH=arm64<br />
BRANCH=android-msm-bullhead-3.10<br />
CROSS_COMPILE=aarch64-linux-android-<br />
DEFCONFIG=bullhead_defconfig<br />
EXTRA_CMDS=''<br />
KERNEL_DIR=private/msm-lge<br />
LINUX_GCC_CROSS_COMPILE_PREBUILTS_BIN=prebuilts/gcc/linux-x86/aarch64/aarch64-linux-android-4.9/bin
FILES="<br />
arch/arm64/boot/Image.gz-dtb<br />
vmlinux<br />
System.map<br />
"<br />
iii,<br />
sudo apt install abootimg<br />
abootimg -x boot.img<br />
abootimg --create bullhead-boot.img -f bootimg.cfg -k Image.gz-dtb -r initrd.img -c "bootsize=????"<br />
fastboot boot bullhead-boot.img <br />

#Build Environment<br />
3#,ubuntu develop env set:<br />
sudo apt-get update<br />
sudo apt-get dist-upgrade<br />
sudo apt-get install openjdk-7-jdk<br />
sudo apt-get install git gnupg flex bison gperf build-essential zip curl libc6-dev libncurses5-dev:i386 x11proto-core-dev libx11-dev:i386 libreadline6-dev:i386 libgl1-mesa-glx:i386 libgl1-mesa-dev g++-multilib mingw32 tofrodos python-markdown libxml2-utils xsltproc zlib1g-dev:i386



#Build Android System<br />

https://android.googlesource.com/kernel/msm/+/android-msm-bullhead-3.10-marshmallow-dr/./build.config<br />

Kernel_Dir=~/Desktop/msm<br />
cd $Kernel_Dir<br />
export PATH=$(pwd)/prebuilts/gcc/linux-x86/aarch64/aarch64-linux-android-4.9/bin:$PATH<br />
export ARCH=arm64<br />
export CROSS_COMPILE=aarch64-linux-android-<br />
make bullhead_defconfig<br />
make -j4<br />
export TARGET_PREBUILT_KERNEL=$Kernel_Dir/arch/arm64/boot/Image.gz-dtb<br />

Build_Dir=~/Desktop/WORKING_DIRECTORY<br />
cd $Build_Dir<br />
source build/envsetup.sh<br />
lunch aosp_bullhead-userdebug<br />
make -j4<br />


#Flash system into device<br />
sudo fastboot flash boot boot.img<br />


#Git<br />
git reset --hard f97f123<br />
git checkout fe89f19<br />
git submodule update --init --recursive<br />

#cp to remote
scp -r ~/Downloads/security/ root@1.1.1.1:/home/
