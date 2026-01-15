#!/bin/sh

pid=$$
cp ./initramfs.cpio.gz "./${pid}chall.cpio.gz"
cp ./flag.txt "./${pid}challflag.txt"

qemu-system-x86_64 \
    -kernel ./bzImage \
    -cpu qemu64 \
    -m 2G \
    -smp 2 \
    -initrd "./${pid}chall.cpio.gz" \
    -append "console=ttyS0 quiet loglevel=3 nokaslr kpti=0" \
    -hdb "./${pid}challflag.txt" \
    -monitor /dev/null \
    -nographic \
    -no-reboot \

rm "./${pid}chall.cpio.gz"
rm "./${pid}challflag.txt"
