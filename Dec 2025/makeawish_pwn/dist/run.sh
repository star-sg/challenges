#!/bin/sh
qemu-system-x86_64 \
    -kernel ./bzImage \
    -cpu qemu64 \
    -m 2G \
    -smp 2 \
    -initrd initramfs.cpio.gz \
    -append "console=ttyS0 quiet loglevel=3 nokaslr kpti=0" \
    -hdb "flag.txt" \
    -monitor /dev/null \
    -nographic \
    -no-reboot \
