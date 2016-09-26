1,How to extract sony kernel and obtain symbol?<br />
binwalk zImage<br />
dd if=zImage bs=17248 skip=1 | gzip -cd > piggy<br />
./kallsymsprint '/home/daniel/Desktop/tegra/arch/arm/boot/piggy' > kallsyms.txt<br />


2,android kernel compile command:
export ARCH=arm<br />
export CROSS_COMPILE=arm-eabi-<br />
export PATH=$PATH:'/home/daniel/Desktop/tegra/prebuilts/gcc/linux-x86/arm/arm-eabi-4.8/bin'<br />
make tegra3_android_defconfig  /  make menuconfig<br />
make -j 16<br />

3,git commit:<br />
git clone--> git config--> git commit--> git push<br />

4, load android kernel<br />
sudo apt install abootimg<br />
abootimg -x boot.img<br />
abootimg --create new-boot.img -f bootimg.cfg -k zImage -r initrd.img -c "bootsize=5744640"<br />
fastboot boot new-boot.img <br />

5,ubuntu ent set:<br />
sudo apt-get install openjdk-7-jdk<br />
sudo apt-get install git gnupg flex bison gperf build-essential zip curl libc6-dev libncurses5-dev:i386 x11proto-core-dev libx11-dev:i386 libreadline6-dev:i386 libgl1-mesa-glx:i386 libgl1-mesa-dev g++-multilib mingw32 tofrodos python-markdown libxml2-utils xsltproc zlib1g-dev:i386



