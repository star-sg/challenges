# syntax=docker/dockerfile:1
FROM ubuntu:latest

## General stuff
RUN apt update && apt upgrade -y
RUN apt-get install qemu-system cron -y
RUN useradd -d /home/ctf/ -m -p ctf -s /bin/bash ctf
RUN echo "ctf:ctf" | chpasswd
WORKDIR /home/ctf

## Challenge files
COPY ynetd . 
COPY initramfs.cpio.gz .
COPY bzImage .
COPY kctf-pow .
COPY run.sh .
COPY pow_run.sh .
COPY start.sh .
COPY flag.txt .
RUN chmod +x /home/ctf/*
RUN (crontab -l 2>/dev/null; echo "*/5 * * * * rm /home/ctf/*chall*") | crontab -
RUN chown ctf:ctf /home/ctf/initramfs.cpio.gz

## Setup
#USER ctf
EXPOSE 4000

CMD /home/ctf/start.sh && ./ynetd -p 4000 ./pow_run.sh

## Run command
## docker run -p 4000:4000 <image name>
