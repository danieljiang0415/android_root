#/bin/bash

unzip $1 -d ./tmp
cd tmp
abootimg -x boot.img
A=`binwalk zImage`
B=`echo $A | awk 'BEGIN{FS="gzip"}{print $1}' | awk '{print $(NF-1)}'`
dd if=zImage bs=$B skip=1 | gzip -cd > pigg
../kallsymsprint pigg > ../kallsyms

cd ..
rm -rf tmp/