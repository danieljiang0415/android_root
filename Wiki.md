wiki





1,How to extract sony kernel and obtain symbol?

2,android kernel compile command:

export ARCH=arm
export CROSS_COMPILE=arm-eabi-
export PATH=$PATH:'/home/daniel/Desktop/tegra/prebuilts/gcc/linux-x86/arm/arm-eabi-4.8/bin'
make tegra3_android_defconfig
make -j 16

3,git commit:
git clone--> git config--> git commit--> git push

4, load android kernel
sudo apt install abootimg
abootimg -x boot.img
abootimg --create new-boot.img -f bootimg.cfg -k zImage -r initrd.img
abootimg --create new-boot.img -f bootimg.cfg -k zImage -r initrd.img -c "bootsize=5744640"
fastboot boot new-boot.img 

